using System;
using System.Xml;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace signtest
{
    class Program
    {
        static void Main(string[] args)
        {

            X509Certificate2 cert = new X509Certificate2(@"VKR-cert.pfx", "1234", X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable); // загрузка сертификата

            XmlSignModule signModule = new XmlSignModule(cert); // cоздание модуля подписи


            Console.WriteLine("Укажите название xml файла");
            string filepatch = Console.ReadLine();

            StreamReader sr = new StreamReader(filepatch, true); //  определение кодировки


            XmlDocument doc = new XmlDocument();
            doc.Load(sr); // загрузка документа

            Console.WriteLine("Выбор режима:");
            Console.WriteLine("1 - подпись");
            Console.WriteLine("2 - проверка подписи");
            int mode = int.Parse(Console.ReadLine());

            switch (mode)
            {
                case 1:
                    signModule.Sign(doc);
                    var filename = Path.GetFileName(filepatch);
                    File.WriteAllText(@"signed_" + filename.Substring(0, filename.Length - 4)+ ".xml", signModule.FormatXml(doc)); // сохранение документа
                    Console.WriteLine(signModule.ValidateXmlDocumentWithCertificate(doc));
                    Console.WriteLine("Готово!");
                    break;

                case 2:
                    if (signModule.ValidateXmlDocumentWithCertificate(doc) == true) // проверка документа 
                    {
                        Console.WriteLine("Подпись документа действительна");
                    }
                    else
                    {
                        Console.WriteLine("Подпись документа некорректна");
                    }
                    
                    break;

                default:
                    Console.WriteLine("Ошибка");
                    break;
            }

            Console.ReadKey();


        }

    }
}

