using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;

namespace Microsoft.Xades.Test
{
    public class TestCase
    {
        public static void Run()
        {
            var envelopedSignatureXmlDocument = new XmlDocument();
            var path = Path.Combine(Environment.CurrentDirectory, "TestItems\\ToSign.xml");


            var text = File.ReadAllText(path, Encoding.UTF8);

            envelopedSignatureXmlDocument.PreserveWhitespace = true;
            envelopedSignatureXmlDocument.LoadXml(text);

            var xadesSignedXml = new XadesSignedXml(envelopedSignatureXmlDocument);

            var reference = new Reference();
            reference.Uri = "";
            //XmlDsigC14NTransform xmlDsigC14NTransform = new XmlDsigC14NTransform();
            //reference.AddTransform(xmlDsigC14NTransform);
            var xmlDsigEnvelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(xmlDsigEnvelopedSignatureTransform);

            xadesSignedXml.AddReference(reference);


            // Obtain certificate
            var certificate = new X509Certificate2(
                Path.Combine(Environment.CurrentDirectory, "TestItems\\R.p12"), "aJ4SCcm2qB");


            // Build selected cert with chain
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

            
            //AddCertificateInfoToSignature();
            var rsaKey = (RSACryptoServiceProvider)certificate.PrivateKey;
            xadesSignedXml.SigningKey = rsaKey;

            KeyInfo keyInfo = new KeyInfo();

            var data = new KeyInfoX509Data(certificate);

            data.AddIssuerSerial(certificate.IssuerName.Name, certificate.SerialNumber);
            data.AddSubjectName(certificate.SubjectName.Name);

            keyInfo.AddClause(data);
            //if (includeKeyValueCheckBox.Checked)
            //{
            //keyInfo.AddClause(new RSAKeyValue(rsaKey));
            //}

            xadesSignedXml.KeyInfo = keyInfo;



            var signId = "xmldsig-" + Guid.NewGuid().ToString();

            xadesSignedXml.Signature.Id = signId;
            XadesObject xadesObject = new XadesObject();
            xadesObject.Id = "XadesObject";
            xadesObject.QualifyingProperties.Target = "#" + signId;



            //AddSignedSignatureProperties(
            //    xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties,
            //    xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties,
            //    xadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties);
            
            var signedSignatureProperties = xadesObject.QualifyingProperties.SignedProperties.
                SignedSignatureProperties;
            
            var cert = new Cert();
            cert.IssuerSerial.X509IssuerName = certificate.IssuerName.Name;
            cert.IssuerSerial.X509SerialNumber = certificate.SerialNumber;
            cert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
            cert.CertDigest.DigestValue = certificate.GetCertHash();
            signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);

            signedSignatureProperties.SigningTime = DateTime.Now;

            signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = true;




            xadesSignedXml.AddXadesObject(xadesObject);

            xadesSignedXml.ComputeSignature();
            


            // Add Chain unsignedProperties = this.xadesSignedXml.UnsignedProperties;
            //unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs();

            //foreach (X509ChainElement element in this.Chain.ChainElements)
            //{
            //    chainCert = new Cert();
            //    chainCert.IssuerSerial.X509IssuerName = element.Certificate.IssuerName.Name;
            //    chainCert.IssuerSerial.X509SerialNumber = element.Certificate.SerialNumber;
            //    chainCert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
            //    chainCert.CertDigest.DigestValue = this.Certificate.GetCertHash();
            //    unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.Id = this.completeCertificateRefsTextBox.Text;
            //    unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection.Add(chainCert);
            //}

            //this.xadesSignedXml.UnsignedProperties = unsignedProperties;
            

            // Insert Signature
            envelopedSignatureXmlDocument.DocumentElement.AppendChild(
                envelopedSignatureXmlDocument.ImportNode(xadesSignedXml.GetXml(), true));
            var xmlElementToShow = envelopedSignatureXmlDocument.DocumentElement;

            var path2 = Path.Combine(Environment.CurrentDirectory, "TestItems\\Signed.xml");
            File.WriteAllText(path2, xmlElementToShow.OuterXml, Encoding.UTF8);

            // Show signature
            var viewSignatureForm = new ViewSignatureForm();
            viewSignatureForm.ShowSignature(xadesSignedXml.SignatureStandard, xmlElementToShow);
            viewSignatureForm.ShowDialog();
        }
    }
}
