<#
using namespace System.Net
# using namespace System.Security.Cryptography.X509Certificates

class TrustAllCertsPolicy : ICertificatePolicy {
    [bool]CheckValidationResult([ServicePoint]$srvPoint, [X509Certificate]$certificate, [WebRequest]$request, [int]$certificateProblem) {
        return $true;
    }
}
#>

if ($PSVersionTable.PSVersion.Major -le 5) {
    try {
        add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@ -ErrorAction SilentlyContinue
    }
    catch {
        
    }
}
