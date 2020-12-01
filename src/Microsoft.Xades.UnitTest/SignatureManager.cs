using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace Microsoft.Xades.UnitTest
{
    public static class XadesSignManager
    {
        /// <summary>
        /// Sign References and return as Detached signature
        /// </summary>
        /// <param name="refereces">List of refereces with key as URL and Stream content</param>
        /// <param name="certificateCollection">Collection must contains PrivateKey with Exportable flag</param>
        /// <returns></returns>
        public static string SignExternalSHA256(IDictionary<Uri, Stream> refereces,
            X509Certificate2Collection certificateCollection)
        {
            // Find one with private key
            X509Certificate2 certificate = null;
            foreach (var cert in certificateCollection)
            {
                if (cert.HasPrivateKey)
                {
                    certificate = cert;
                }
            }

            // Build main element
            var xadesSignedXml = new XadesSignedXml(new XmlDocument());

            // Create Signature ID
            var signGuid = Guid.NewGuid().ToString();
            var signId = "xmldsig-" + signGuid;

            // Add reference to SIGN
            int i = 0;
            foreach (var r in refereces)
            {
                Reference reference = new Reference(r.Value);
                //reference.AddTransform(new XmlDsigC14NTransform());
                reference.Id = $"{signId}-ref{i++}";
                reference.Uri = r.Key.ToString();
                reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";
                xadesSignedXml.AddReference(reference);
            }

            // Build selected cert with all chain
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            _ = chain.Build(certificate);

            // Add Certificate Info To Signature
            var exportedKeyMaterial = certificate.PrivateKey.ToXmlString(includePrivateParameters: true);

            // Change Provider to support SHA256
            // https://stackoverflow.com/questions/29005876/signedxml-compute-signature-with-sha256
            var key = new RSACryptoServiceProvider(new CspParameters(24 /* PROV_RSA_AES */));
            key.PersistKeyInCsp = false;
            key.FromXmlString(exportedKeyMaterial);

            // Change signature method
            xadesSignedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            xadesSignedXml.SigningKey = key;

            KeyInfo keyInfo = new KeyInfo();
            var data = new KeyInfoX509Data(certificate);
            data.AddIssuerSerial(certificate.IssuerName.Name.Replace(", ", ","), certificate.SerialNumber);
            data.AddSubjectName(certificate.SubjectName.Name);
            keyInfo.AddClause(data);
            xadesSignedXml.KeyInfo = keyInfo;

            xadesSignedXml.Signature.Id = signId;
            XadesObject xadesObject = new XadesObject();
            xadesObject.Id = null;
            xadesObject.QualifyingProperties.Target = "#" + signId;

            var signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;

            // Mapping certificate list
            var certList = new List<Cert>();
            foreach (var c in certificateCollection.Cast<X509Certificate2>().Reverse())
            {
                var cert = new Cert();
                var dataSingleCert = new KeyInfoX509Data(certificate);
                dataSingleCert.AddIssuerSerial(c.IssuerName.Name, c.SerialNumber);
                cert.IssuerSerial.X509IssuerName = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).IssuerName.Replace(", ", ",");
                cert.IssuerSerial.X509SerialNumber = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).SerialNumber;
                cert.CertDigest.DigestMethod.Algorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

                // Calculate SHA256
                // https://stackoverflow.com/questions/34634453/hash-x509-certificate-with-sha-256-in-c-sharp
                using (var hasher = SHA256.Create())
                {
                    var hash = hasher.ComputeHash(c.RawData);
                    cert.CertDigest.DigestValue = hash;// c.GetCertHash();
                }

                certList.Add(cert);
            }
            signedSignatureProperties.SigningCertificate.CertCollection.AddRange(certList);

            xadesObject.QualifyingProperties.SignedProperties.Id = signId + "-signedprops";
            signedSignatureProperties.SigningTime = DateTime.Now;
            signedSignatureProperties.SignaturePolicyIdentifierSpecified = false;

            xadesSignedXml.AddXadesObject(xadesObject,
                new XmlDsigC14NTransform(),
                "http://www.w3.org/2001/04/xmlenc#sha256",
                "http://uri.etsi.org/01903#SignedProperties");

            xadesSignedXml.ComputeSignature();

            return xadesSignedXml.GetXml().OuterXml;
        }

        /// <summary>
        /// Method used to sign xml with Xades Enveloped Signature
        /// </summary>
        /// <param name="stringXml">Xml to sign</param>
        /// <param name="certificateCollection">Imported collection with cert path one of them must include private key</param>
        /// <returns></returns>
        public static string Sign(string stringXml,
            X509Certificate2Collection certificateCollection)
        {
            X509Certificate2 certificate = null;

            // Find one with private key
            foreach (var cert in certificateCollection)
            {
                if (cert.HasPrivateKey)
                {
                    certificate = cert;
                }
            }

            var signGuid = Guid.NewGuid().ToString();
            var signId = "xmldsig-" + signGuid;

            var envelopedSignatureXmlDocument = new XmlDocument();
            envelopedSignatureXmlDocument.PreserveWhitespace = true;
            envelopedSignatureXmlDocument.LoadXml(stringXml);

            var xadesSignedXml = new XadesSignedXml(envelopedSignatureXmlDocument);

            // Create reference
            var reference = new Reference
            {
                Uri = "",
                Id = signId + "-ref0"
            };
            var xmlDsigEnvelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(xmlDsigEnvelopedSignatureTransform);
            xadesSignedXml.AddReference(reference);

            // Build selected cert with chain
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllFlags;
            var b = chain.Build(certificate);

            var rsaKey = (RSACryptoServiceProvider)certificate.PrivateKey;
            xadesSignedXml.SigningKey = rsaKey;

            KeyInfo keyInfo = new KeyInfo();
            var data = new KeyInfoX509Data(certificate);
            data.AddIssuerSerial(certificate.IssuerName.Name.Replace(", ", ","), certificate.SerialNumber);
            data.AddSubjectName(certificate.SubjectName.Name);
            keyInfo.AddClause(data);
            xadesSignedXml.KeyInfo = keyInfo;

            xadesSignedXml.Signature.Id = signId;
            XadesObject xadesObject = new XadesObject();
            xadesObject.Id = null;
            xadesObject.QualifyingProperties.Target = "#" + signId;

            var signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;

            // Mapping certificate list
            var certList = new List<Cert>();
            foreach (var c in certificateCollection)
            {
                var cert = new Cert();

                var dataSingleCert = new KeyInfoX509Data(certificate);
                dataSingleCert.AddIssuerSerial(c.IssuerName.Name, c.SerialNumber);

                cert.IssuerSerial.X509IssuerName = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).IssuerName.Replace(", ", ",");
                cert.IssuerSerial.X509SerialNumber = ((X509IssuerSerial)dataSingleCert.IssuerSerials[0]).SerialNumber;
                cert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
                cert.CertDigest.DigestValue = c.GetCertHash();
                certList.Add(cert);
            }
            signedSignatureProperties.SigningCertificate.CertCollection.AddRange(certList);

            xadesObject.QualifyingProperties.SignedProperties.Id = signId + "-signedprops";
            signedSignatureProperties.SigningTime = DateTime.Now;
            signedSignatureProperties.SignaturePolicyIdentifierSpecified = false;

            xadesSignedXml.AddXadesObject(xadesObject, new XmlDsigC14NTransform());
            xadesSignedXml.ComputeSignature();

            // Insert Signature
            envelopedSignatureXmlDocument.DocumentElement.AppendChild(
                envelopedSignatureXmlDocument.ImportNode(xadesSignedXml.GetXml(), true));
            var xmlElementToShow = envelopedSignatureXmlDocument;

            return xmlElementToShow.OuterXml;
        }
    }
}
