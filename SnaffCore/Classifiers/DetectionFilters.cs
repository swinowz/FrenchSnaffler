using System;

namespace SnaffCore.Classifiers
{
    internal static class DetectionFilters
    {
        // Public vendor documentation fixtures should not become high-confidence
        // secrets. This is deliberately exact and narrowly scoped.
        public static bool IsKnownPlaceholder(ClassifierRule rule, TextResult result)
        {
            if (rule == null || result == null || string.IsNullOrEmpty(result.MatchedValue)) return false;
            return rule.RuleName == "KeepAwsKeysInCode" &&
                result.MatchedValue.IndexOf("AKIAIOSFODNN7EXAMPLE", StringComparison.OrdinalIgnoreCase) >= 0;
        }
    }
}
