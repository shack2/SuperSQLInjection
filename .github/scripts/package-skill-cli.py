#!/usr/bin/env python3
"""把 CMD Native AOT 产物安装到 Skill，并生成可分发的 .skill 包。

Native AOT 不能跨操作系统构建：先在 Windows/Linux 分别执行对应 publish 脚本，
再在任一系统执行本脚本。默认要求两个平台都有新 publish 产物；仅做结构预览时，
可通过 --reuse-existing linux-x64 显式复用 Skill 中的旧 Linux 文件。
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import stat
import sys
from datetime import datetime, timezone
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[2]
SKILL = ROOT / "skills" / "supersqlinjectionv2-cmd"
RIDS = ("win-x64", "linux-x64")
EXECUTABLES = {
    "win-x64": "SuperSQLInjectionV2.Cmd.exe",
    "linux-x64": "SuperSQLInjectionV2.Cmd",
}
QUICKJS = {"win-x64": "libquickjs.dll", "linux-x64": "libquickjs.so"}
# 这些文件由本机运行产生，不属于可分发规则资源。
RUNTIME_FILES = {
    "config/inject_records.json",
    "config/injection/hit_count.json",
    "config/lastconfig.json",
    "config/rules/proxies.json",
}
RUNTIME_DIRS = {"config/sessions", "output"}


def project_version(path: Path) -> str:
    match = re.search(r"<Version>([^<]+)</Version>", path.read_text(encoding="utf-8"))
    if not match:
        raise RuntimeError(f"无法读取 Version：{path}")
    return match.group(1).strip()


def version() -> str:
    versions = {
        "CMD": project_version(ROOT / "SuperSQLInjectionV2.Cmd" / "SuperSQLInjectionV2.Cmd.csproj"),
        "桌面端": project_version(ROOT / "SuperSQLInjectionV2.Desktop" / "SuperSQLInjectionV2.Desktop.csproj"),
    }
    skill_text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    match = re.search(r"^版本：([^（\r\n]+)（与 SuperSQLInjectionV2 桌面端和 CMD 同步）。$", skill_text, re.MULTILINE)
    if not match:
        raise RuntimeError("SKILL.md 缺少“版本：x.y.z（与 SuperSQLInjectionV2 桌面端和 CMD 同步）。”")
    versions["Skill"] = match.group(1).strip()
    if len(set(versions.values())) != 1:
        raise RuntimeError("三端版本不一致：" + "，".join(f"{name}={value}" for name, value in versions.items()))
    print("版本一致：" + "，".join(f"{name}={value}" for name, value in versions.items()))
    return versions["CMD"]


def ignored(relative: Path) -> bool:
    value = relative.as_posix()
    if value in RUNTIME_FILES:
        return True
    if any(value == directory or value.startswith(directory + "/") for directory in RUNTIME_DIRS):
        return True
    return relative.suffix.lower() in {".pdb", ".dbg", ".dwarf"}


def copy_publish(rid: str, reuse: bool) -> tuple[Path, str]:
    publish = ROOT / "SuperSQLInjectionV2.Cmd" / "bin" / "Release" / "net10.0" / rid / "publish"
    destination = SKILL / "assets" / "bin" / rid
    executable = EXECUTABLES[rid]
    quickjs = QUICKJS[rid]
    source = publish if (publish / executable).is_file() else None
    source_kind = "publish"

    if source is None and reuse and (destination / executable).is_file():
        source = destination
        source_kind = "reused-existing"
    if source is None:
        raise FileNotFoundError(
            f"{rid} 缺少新构建产物：{publish / executable}\n"
            f"请先在对应操作系统执行 Native AOT publish；确需复用旧文件时显式传 --reuse-existing {rid}。"
        )

    for required in (executable, quickjs):
        if not (source / required).is_file():
            raise FileNotFoundError(f"{rid} 缺少 {required}：{source / required}")
    if not (source / "config" / "payload").is_dir() or not (source / "config" / "injection").is_dir():
        raise FileNotFoundError(f"{rid} 的 config/payload 或 config/injection 不完整：{source / 'config'}")

    staging = destination.with_name(destination.name + ".staging")
    if staging.exists():
        shutil.rmtree(staging)
    staging.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, staging, ignore=lambda directory, names: [
        name for name in names if ignored((Path(directory) / name).relative_to(source))
    ])
    if destination.exists():
        shutil.rmtree(destination)
    staging.replace(destination)

    executable_path = destination / executable
    if rid == "linux-x64":
        executable_path.chmod(executable_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    # 复制后再次检查，防止过滤规则误删必要资源。
    for required in (executable, quickjs, "config/payload/mysql.txt", "config/injection/boolean_blind.xml"):
        if not (destination / required).is_file():
            raise RuntimeError(f"{rid} 安装后缺少必要文件：{destination / required}")
    for relative in sorted(RUNTIME_FILES):
        if (destination / relative).exists():
            raise RuntimeError(f"{rid} 包含不应分发的运行态文件：{relative}")
    if (destination / "config" / "sessions").exists():
        raise RuntimeError(f"{rid} 包含不应分发的 config/sessions")

    file_count = sum(1 for path in destination.rglob("*") if path.is_file())
    print(f"[{rid}] {source_kind}: {file_count} 个文件 -> {destination}")
    return destination, source_kind


def write_build_info(entries: dict[str, str], app_version: str) -> Path:
    path = SKILL / "assets" / "bin" / "BUILDINFO.json"
    payload = {
        "version": app_version,
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "platforms": {
            rid: {
                "executable": EXECUTABLES[rid],
                "quickjs": QUICKJS[rid],
                "source": entries[rid],
                "currentBuildVerified": entries[rid] == "publish",
            }
            for rid in RIDS
        },
    }
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def zip_skill(destination: Path) -> tuple[int, str]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(destination, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(SKILL.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(SKILL)
            archive_name = (Path(SKILL.name) / relative).as_posix()
            if relative.as_posix() == "assets/bin/linux-x64/SuperSQLInjectionV2.Cmd":
                # Windows 没有 POSIX 执行位，显式写入 zip Unix 属性。
                info = ZipInfo.from_file(path, archive_name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o755) << 16
                archive.writestr(info, path.read_bytes(), compress_type=ZIP_DEFLATED, compresslevel=9)
            else:
                archive.write(path, archive_name)
    with ZipFile(destination) as archive:
        bad = archive.testzip()
        if bad:
            raise RuntimeError(f"zip CRC 校验失败：{bad}")
        names = set(archive.namelist())
        for rid in RIDS:
            for name in (EXECUTABLES[rid], QUICKJS[rid], "config/payload/mysql.txt"):
                expected = f"{SKILL.name}/assets/bin/{rid}/{name}"
                if expected not in names:
                    raise RuntimeError(f"zip 缺少：{expected}")
        linux_info = archive.getinfo(f"{SKILL.name}/assets/bin/linux-x64/{EXECUTABLES['linux-x64']}")
        if (linux_info.external_attr >> 16) & 0o111 == 0:
            raise RuntimeError("zip 中 Linux 可执行文件没有执行权限")
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    return destination.stat().st_size, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reuse-existing", choices=RIDS, action="append", default=[],
                        help="没有新 publish 时复用 Skill 中已有平台文件（会在 BUILDINFO 标记，慎用）")
    parser.add_argument("--zip", type=Path, help="输出 .skill/.zip 路径；默认 dist/supersqlinjectionv2-cmd.skill")
    parser.add_argument("--no-zip", action="store_true", help="只安装 assets/bin，不生成 Skill 包")
    args = parser.parse_args()

    for required in (SKILL / "SKILL.md", SKILL / "references" / "cli-reference.md"):
        if not required.is_file():
            raise FileNotFoundError(f"Skill 文档缺失：{required}")
    app_version = version()
    entries: dict[str, str] = {}
    for rid in RIDS:
        _, entries[rid] = copy_publish(rid, rid in args.reuse_existing)
    info = write_build_info(entries, app_version)
    print(f"构建信息：{info}")
    if not args.no_zip:
        output = args.zip or ROOT / "dist" / "supersqlinjectionv2-cmd.skill"
        if not output.is_absolute():
            output = ROOT / output
        size, digest = zip_skill(output.resolve())
        print(f"Skill 包：{output.resolve()}")
        print(f"大小：{size} 字节；SHA256：{digest}")
    if args.reuse_existing:
        print("警告：包内包含显式复用的旧平台文件，不等同于双平台当前源码构建：" + ", ".join(args.reuse_existing), file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"打包失败：{error}", file=sys.stderr)
        raise SystemExit(1)
