using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Text;
using System.Text.Json.Serialization;


namespace SuperSQLInjectionV2.Models;

[JsonConverter(typeof(JsonStringEnumConverter<ErrorInjectType>))]
public enum ErrorInjectType
{
    [Description("FloorRand")] FloorRand,
    [Description("RawToHex")] RawToHex,
}