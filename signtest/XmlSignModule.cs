using System;
using System.Text;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography;

namespace signtest
{
    class XmlSignModule
    {
        protected X509Certificate2 cert;

        public XmlSignModule(X509Certificate2 certificate)
        {
            cert = certificate;
        }


        public void Sign(XmlDocument doc)
        {
            
            RSAPKCS1SHA256SignatureDescription.Register(); // регистрация дескриптора
            if (doc.DocumentElement.Attributes["ID"] == null) doc.DocumentElement.SetAttribute("ID", Guid.NewGuid().ToString()); // задаем id если его нету

            RSACryptoServiceProvider key = new RSACryptoServiceProvider(new CspParameters(24)); // создание ключа
            key.PersistKeyInCsp = false;
            key.FromXmlString(
                cert.PrivateKey.ToXmlString(true) // берем ключ из сертификата
            );

            Reference reference = new Reference(); // Подписываем весь документ
            reference.Uri = "#" + doc.DocumentElement.Attributes["ID"].Value;
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            //reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            KeyInfo keyInfo = new KeyInfo(); 
            keyInfo.AddClause(new KeyInfoX509Data(cert)); // информация о ключе из сертификата

            SignedXml sig = new SignedXml(doc); // формирования подписи
            sig.SigningKey = key;
            sig.AddReference(reference);
            sig.SignedInfo.CanonicalizationMethod = "http://www.w3.org/2001/10/xml-exc-c14n#"; 
            sig.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
            sig.KeyInfo = keyInfo;
            sig.ComputeSignature();

            XmlElement signature = sig.GetXml(); // элемент подписи

            doc.DocumentElement.InsertBefore(signature, doc.DocumentElement.ChildNodes[0]); // вставляем элемент подписи в начало
        }


        public bool ValidateXmlDocumentWithCertificate(XmlDocument doc)
        {
            try
            {
                X509Certificate2 cert = new X509Certificate2(
                    Convert.FromBase64String(((XmlElement)doc.GetElementsByTagName("Signature")[0]).GetElementsByTagName("X509Certificate")[0].InnerText)); // конвертация элемента по тегу
                try
                {
                    XmlElement signatureNode = (XmlElement)doc.GetElementsByTagName("Signature")[0]; // загружаем элемент с подписью
                    SignedXml signedXml = new SignedXml(doc);
                    signedXml.LoadXml(signatureNode);
                    return signedXml.CheckSignature(cert, true);
                }
                catch
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }



        public string FormatXml(XmlDocument doc)
        {
            StringBuilder stringBuilder = new StringBuilder();

            XmlWriterSettings settings = new XmlWriterSettings(); // создаем настройки
            settings.Indent = true; // отступы элементов

            using (var xmlWriter = XmlWriter.Create(stringBuilder, settings))
            {
                doc.Save(xmlWriter); // сохраняем документ
            }

            return stringBuilder.ToString();
        }




    }
}
