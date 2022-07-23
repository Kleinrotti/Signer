using System;
using System.Linq;
using System.Reflection;
using System.Runtime.Serialization;

namespace Signer
{
    public static class Extension
    {
        public static string GetEnumMemberValue<T>(this T value) where T : Enum
        {
            return typeof(T)
                .GetTypeInfo()
                .DeclaredMembers
                .SingleOrDefault(x => x.Name == value.ToString())
                ?.GetCustomAttribute<EnumMemberAttribute>(false)
                ?.Value;
        }
    }

    public enum TimestampHash
    {
        [EnumMember(Value = "1.3.14.3.2.26")]
        SHA1,

        [EnumMember(Value = "2.16.840.1.101.3.4.2.1")]
        SHA256,

        [EnumMember(Value = "2.16.840.1.101.3.4.2.2")]
        SHA384,

        [EnumMember(Value = "2.16.840.1.101.3.4.2.3")]
        SHA512
    }
}