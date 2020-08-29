using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SocketClient
{
    class CustomOperation
    {
        public static void Custom()
        {
            char[] pass = Console.ReadLine().ToCharArray();
            char[] key = Console.ReadLine().ToCharArray();
			var modifier = 40;
			var upper = 126;

			// 1. SHIFT AND REVERSE
			List<byte> bytes = Encoding.ASCII.GetBytes(pass).ToList();
            var shifted = bytes.Select(x =>
            {
                var newValue = x - modifier;
                var lappedValue = upper - newValue;
                return (newValue > upper) ? lappedValue : newValue;
            }).ToList();

            shifted.Reverse();


			// 2. CIPHER USING PLAYFAIR
			string passAsString = String.Concat(shifted.Select(x => (char)x));
			var keyAsString = String.Concat(key);

			// encrypt using Playfair Cipher 
			var enciphered = Encipher(passAsString, keyAsString);
			Console.WriteLine(enciphered);


			// 3. DECIPHER USING PLAYFAÌR
			var deciphered = Decipher(enciphered, "Buger");
			Console.WriteLine(deciphered);


			// 4. REVERSE AND SHIFT
			var reverseDeciphered = deciphered.Reverse().ToArray();

			List<byte> newBytes = Encoding.ASCII.GetBytes(reverseDeciphered).ToList();

			var reverseShifted = newBytes.Select(x =>
			{
				var newValue = x + modifier;
				var lappedValue = upper - newValue;
				return (newValue > upper) ? lappedValue : newValue;
			}).ToList();

			reverseShifted.ForEach(x =>
			{
				Console.Write((char)x);
			});


			Console.ReadKey();
        }

		private static int Mod(int a, int b)
		{
			return (a % b + b) % b;
		}

		private static List<int> FindAllOccurrences(string str, char value)
		{
			List<int> indexes = new List<int>();

			int index = 0;
			while ((index = str.IndexOf(value, index)) != -1)
				indexes.Add(index++);

			return indexes;
		}

		private static string RemoveAllDuplicates(string str, List<int> indexes)
		{
			string retVal = str;

			for (int i = indexes.Count - 1; i >= 1; i--)
				retVal = retVal.Remove(indexes[i], 1);

			return retVal;
		}

		private static char[,] GenerateKeySquare(string key)
		{
			char[,] keySquare = new char[5, 5]; // Multidimensional Array
			string defaultKeySquare = "!#%&()+,-./0123456789:;<=>?@ABCDEFGHIKLMNOPQRSTUVWXYZ_|abcdefghijklmnopqrstuvwxyz";

			

			//"!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIKLMNOPQRSTUVWXYZ[\\]^_|`abcdefghijklmnopqrstuvwxyz{|}~"
			string tempKey = key.ToUpper();

			tempKey = tempKey.Replace("J", ""); // Remove J (Playfair)
			tempKey += defaultKeySquare; // Add Keysquare to end of word

			for (int i = 0; i < 25; ++i)
			{
				List<int> indexes = FindAllOccurrences(tempKey, defaultKeySquare[i]); // Gets index position of all duplicates
				tempKey = RemoveAllDuplicates(tempKey, indexes); // Based on indexes, removes duplicates
			}

			tempKey = tempKey.Substring(0, 25); // Only give us the 25 first characters

			for (int i = 0; i < 25; ++i)
				keySquare[(i / 5), (i % 5)] = tempKey[i]; // Fill Keysquare on all rows and columns

			return keySquare;
		}

		private static void GetPosition(ref char[,] keySquare, char ch, ref int row, ref int col)
		{
			if (ch == 'J')
				GetPosition(ref keySquare, 'I', ref row, ref col);

			for (int i = 0; i < 5; ++i)
				for (int j = 0; j < 5; ++j)
					if (keySquare[i, j] == ch)
					{
						row = i;
						col = j;
					}
		}

		private static char[] SameRow(ref char[,] keySquare, int row, int col1, int col2, int encipher)
		{
			return new char[] { keySquare[row, Mod((col1 + encipher), 5)], keySquare[row, Mod((col2 + encipher), 5)] };
		}

		private static char[] SameColumn(ref char[,] keySquare, int col, int row1, int row2, int encipher)
		{
			return new char[] { keySquare[Mod((row1 + encipher), 5), col], keySquare[Mod((row2 + encipher), 5), col] };
		}

		private static char[] SameRowColumn(ref char[,] keySquare, int row, int col, int encipher)
		{
			return new char[] { keySquare[Mod((row + encipher), 5), Mod((col + encipher), 5)], keySquare[Mod((row + encipher), 5), Mod((col + encipher), 5)] };
		}

		private static char[] DifferentRowColumn(ref char[,] keySquare, int row1, int col1, int row2, int col2)
		{
			return new char[] { keySquare[row1, col2], keySquare[row2, col1] };
		}

		private static string RemoveOtherChars(string input)
		{
			string output = input;

			for (int i = 0; i < output.Length; ++i)
				if (!char.IsLetter(output[i]))
					output = output.Remove(i, 1);

			return output;
		}

		private static string AdjustOutput(string input, string output)
		{
			StringBuilder retVal = new StringBuilder(output);

			for (int i = 0; i < input.Length; ++i)
			{
				if (!char.IsLetter(input[i]))
					retVal = retVal.Insert(i, input[i].ToString());

				if (char.IsLower(input[i]))
					retVal[i] = char.ToLower(retVal[i]); // Adjusts character to LOWER version, based on original word
			}

			return retVal.ToString();
		}

		private static string Cipher(string input, string key, bool encipher)
		{
			string retVal = string.Empty;
			char[,] keySquare = GenerateKeySquare(key); // Creates Keysquare with our provided key
			int e = encipher ? 1 : -1; // Checks if we're encrypting or decrypting

			if ((input.Length % 2) != 0) // If the input is not divisible by 2, add an X at the end
				input += "X";

			for (int i = 0; i < input.Length; i += 2)
			{
				int row1 = 0;
				int col1 = 0;
				int row2 = 0;
				int col2 = 0;

				GetPosition(ref keySquare, char.ToUpper(input[i]), ref row1, ref col1);
				GetPosition(ref keySquare, char.ToUpper(input[i + 1]), ref row2, ref col2);

				if (row1 == row2 && col1 == col2)
				{
					retVal += new string(SameRowColumn(ref keySquare, row1, col1, e));
				}
				else if (row1 == row2)
				{
					retVal += new string(SameRow(ref keySquare, row1, col1, col2, e));
				}
				else if (col1 == col2)
				{
					retVal += new string(SameColumn(ref keySquare, col1, row1, row2, e));
				}
				else
				{
					retVal += new string(DifferentRowColumn(ref keySquare, row1, col1, row2, col2));
				}
			}

			return AdjustOutput(input, retVal);
		}

		public static string Encipher(string input, string key)
		{
			return Cipher(input, key, true);
		}

		public static string Decipher(string input, string key)
		{
			return Cipher(input, key, false);
		}
	}
    

}
