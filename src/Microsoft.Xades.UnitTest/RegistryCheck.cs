using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security;
using System.Text;
using System.Threading.Tasks;

namespace Microsoft.Xades.UnitTest
{
    public static class RegistryCheck
    {
        private static bool? s_allowDetachedSignature = null;

        internal static bool AllowDetachedSignature()
        {
            // Allow machine administrators to specify that detached signatures can be processed.
            // The default behavior is to throw when processing a detached signature,
            // but a REG_DWORD or REG_QWORD value of 1 will revert.
            if (s_allowDetachedSignature.HasValue)
            {
                return s_allowDetachedSignature.Value;
            }

            long numericValue = GetNetFxSecurityRegistryValue("SignedXmlAllowDetachedSignature", 0);
            bool allowDetachedSignature = numericValue != 0;

            s_allowDetachedSignature = allowDetachedSignature;
            return s_allowDetachedSignature.Value;
        }

        private static long GetNetFxSecurityRegistryValue(string regValueName, long defaultValue)
        {
            try
            {
                using (RegistryKey securityRegKey = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\.NETFramework\Security", false))
                {
                    if (securityRegKey != null)
                    {
                        object regValue = securityRegKey.GetValue(regValueName);
                        if (regValue != null)
                        {
                            RegistryValueKind valueKind = securityRegKey.GetValueKind(regValueName);
                            if (valueKind == RegistryValueKind.DWord || valueKind == RegistryValueKind.QWord)
                            {
                                return Convert.ToInt64(regValue, CultureInfo.InvariantCulture);
                            }
                        }
                    }
                }
            }
            catch (SecurityException) { /* we could not open the key - that's fine, we can proceed with the default value */ }

            return defaultValue;
        }
    }
}
