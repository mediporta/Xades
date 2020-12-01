using System;
using System.IO;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography.X509Certificates;
using System.Collections.Generic;

namespace Microsoft.Xades.UnitTest
{
    [TestClass]
    public class UnitTest1
    {
        [TestMethod]
        public void SignExternalWithSHA256()
        {
            var cert = GetMyCert();
            var docPath = GetFilePathToSign();

            var references = new Dictionary<Uri, Stream>();
            references.Add(new Uri("https://www.w3schools.com/xml/note.xml"), File.OpenRead(docPath));

            // certificate must be exportable
            var signature = XadesSignManager.SignExternalSHA256(references, cert);

            Assert.IsNotNull(signature);
        }

        [TestMethod]
        public void SignXmlSHA1()
        {
            var cert = GetMyCert();
            var docPath = GetFilePathToSign();
            var xml = File.ReadAllText(docPath);

            var signature = XadesSignManager.Sign(xml, cert);

            Assert.IsNotNull(signature);
        }

        private string GetFilePathToSign()
        {
            //Downloaded file "https://www.w3schools.com/xml/note.xml"

            return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Data/note.xml");
        }

        /// <summary>
        /// Change body of this method to correct get your certificate with Private Key
        /// </summary>
        /// <returns></returns>
        private X509Certificate2Collection GetMyCert()
        {
            var path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory,
                "Data/public_privatekey.pfx");
            var cert = File.ReadAllBytes(path);

            var certificate2Collection = new X509Certificate2Collection();

            // Exportable for convert to SHA256 signature
            certificate2Collection.Import(cert, "password", X509KeyStorageFlags.Exportable);

            return certificate2Collection;
        }
    }
}
