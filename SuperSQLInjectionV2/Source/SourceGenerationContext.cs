using SuperSQLInjectionV2.Models;
using SuperSQLInjectionV2.Models.Data;
using SuperSQLInjectionV2.Tools.Update;
using SuperSQLInjectionV2.ViewModels;
using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Serialization.Metadata;

namespace SuperSQLInjectionV2.Source
{
    //别忘记加这么一句，每个要用到序列化反序列化的对象都要加
    [JsonSerializable(typeof(AppConfig))]
    //伴随请求统一配置（前置随机值抓取/后置二次注入）
    [JsonSerializable(typeof(CompanionRequestConfig))]
    [JsonSerializable(typeof(EncodeConfig))]
    [JsonSerializable(typeof(ProxyConfig))]
    [JsonSerializable(typeof(ByPassConfig))]
    //统一编码工具链（tamper/编码处理合并）+ 替换项/UA项
    [JsonSerializable(typeof(EncodeToolModel))]
    [JsonSerializable(typeof(ScriptTamperModel))]
    [JsonSerializable(typeof(ReplaceModel))]
    [JsonSerializable(typeof(UaItem))]
    [JsonSerializable(typeof(DataConfig))]
    [JsonSerializable(typeof(BoolInjectType))]
    [JsonSerializable(typeof(InjectType))]
    [JsonSerializable(typeof(DBType))]
    [JsonSerializable(typeof(ErrorInjectType))]
    [JsonSerializable(typeof(String))]
    [JsonSerializable(typeof(string))]
    [JsonSerializable(typeof(bool))]
    [JsonSerializable(typeof(byte))]
    [JsonSerializable(typeof(int))]
    [JsonSerializable(typeof(long))]
    //注入记录持久化
    [JsonSerializable(typeof(InjectRecord))]
    [JsonSerializable(typeof(List<InjectRecord>))]
    //盲注进度/值缓存
    [JsonSerializable(typeof(Dictionary<string, string>))]
    //dump任务级断点续传
    [JsonSerializable(typeof(Dictionary<string, int>))]
    //库表列结构导出
    [JsonSerializable(typeof(DataDumpViewModel.DBStructNodeDto))]
    [JsonSerializable(typeof(List<DataDumpViewModel.DBStructNodeDto>))]
    //n-gram在线学习增量
    [JsonSerializable(typeof(NgramDeltaDto))]
    [JsonSerializable(typeof(Dictionary<string, Dictionary<string, int>>))]
    //规则库独立文件（RuleStore：config/rules/）
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.ChainEntry))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.ChainEntry>))]
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.BuiltinEntry))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.BuiltinEntry>))]
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.ScriptEntry))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.ScriptEntry>))]
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.DynamicRuleDto))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.DynamicRuleDto>))]
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.ProxyDto))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.ProxyDto>))]
    [JsonSerializable(typeof(SuperSQLInjectionV2.Bypass.RuleStore.HashApiDto))]
    [JsonSerializable(typeof(List<SuperSQLInjectionV2.Bypass.RuleStore.HashApiDto>))]
    [JsonSerializable(typeof(List<ReplaceModel>))]
    //软件更新
    [JsonSerializable(typeof(CheckUpdateResponse))]
    [JsonSerializable(typeof(UpdateManifest))]
    [JsonSerializable(typeof(ManifestFileEntry))]
    [JsonSerializable(typeof(FeedbackRequest))]
    [JsonSourceGenerationOptions(WriteIndented = true, Converters = [
        typeof(JsonStringEnumConverter<InjectType>),
        typeof(JsonStringEnumConverter<BoolInjectType>)
        // 为每个枚举类型添加一个泛型转换器
    ])]
    internal partial class SourceGenerationContext : JsonSerializerContext
    {
    }

    /// <summary>
    /// 全局共享JSON序列化选项：统一挂源生成Context作为TypeInfoResolver（JIT/AOT行为一致）。
    /// 源生成器能看到同编译内MVVM Toolkit生成的属性，配置持久化完整；
    /// 调用方一律通过CompactInfo/IndentedInfo/WebInfo拿JsonTypeInfo走无警告重载。
    /// </summary>
    public static class JsonCtx
    {
        /// <summary>紧凑输出（进度/缓存等机器读写文件）</summary>
        public static readonly JsonSerializerOptions Compact = new JsonSerializerOptions { TypeInfoResolver = SourceGenerationContext.Default };

        /// <summary>缩进输出（配置/模板等人工可读文件），与历史反射序列化行为一致（枚举按数字）</summary>
        public static readonly JsonSerializerOptions Indented = new JsonSerializerOptions { TypeInfoResolver = SourceGenerationContext.Default, WriteIndented = true };

        /// <summary>Web风格（更新服务接口，camelCase）</summary>
        public static readonly JsonSerializerOptions Web = new(JsonSerializerDefaults.Web) { TypeInfoResolver = SourceGenerationContext.Default };

        // ===== AOT安全的TypeInfo桥接：Serialize(value, options)泛型重载带[RequiresUnreferencedCode]，
        // 改用Serialize(value, JsonTypeInfo)重载彻底消除IL2026/IL3050警告。
        // JIT下options无resolver时GetTypeInfo回退反射（保留MVVM Toolkit生成属性的完整序列化行为）；
        // AOT下resolver命中源生成Context，零反射零动态代码。 =====

        /// <summary>紧凑输出的TypeInfo（对应Compact选项）</summary>
        public static JsonTypeInfo<T> CompactInfo<T>() => (JsonTypeInfo<T>)Compact.GetTypeInfo(typeof(T));

        /// <summary>缩进输出的TypeInfo（对应Indented选项）</summary>
        public static JsonTypeInfo<T> IndentedInfo<T>() => (JsonTypeInfo<T>)Indented.GetTypeInfo(typeof(T));

        /// <summary>Web风格的TypeInfo（对应Web选项）</summary>
        public static JsonTypeInfo<T> WebInfo<T>() => (JsonTypeInfo<T>)Web.GetTypeInfo(typeof(T));
    }
}
