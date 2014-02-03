// Asn1Parser.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
// Published under the CECILL-B Free Software license agreement.
// (http://www.cecill.info/licences/Licence_CeCILL-B_V1-en.txt)
// 
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
// WHETHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED 
// WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
// THE ENTIRE RISK OF USE OR RESULTS IN CONNECTION WITH THE USE OF THIS CODE 
// AND INFORMATION REMAINS WITH THE USER. 
//

using System;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Data;
using System.IO;
using System.Xml;
using System.Text;

namespace Microsoft.Xades.Test
{
	/// <summary>
	/// Summary description for Asn1Parser.
	/// </summary>
	public class Asn1Parser
	{
		public const int TagNumberMask = 0x1F; //Bits 5 - 1
		public const int TagConstructedFlagMask = 0x20; //Bit 6
		public const int TagClassMask = 0xC0; //Bits 7 - 8
		public const int LEN_XTND = 0x80; //Indefinite or long form
		public const long LEN_MASK = 0x7F; //Bits 7 - 1
		public const int MAX_OID_SIZE = 32;

		private XmlNode parseTree;

		public Asn1Parser()
		{
			this.parseTree = null;
		}

		public XmlNode ParseTree
		{
			get
			{
				return this.parseTree;
			}
		}

		private string CheckText(byte[] byteArrayToTest)
		{
			bool itIsText = true;
			char charToTest;
			long charCounter = 0;
			StringBuilder retVal;
			
			retVal = new StringBuilder();
			while (itIsText && charCounter < byteArrayToTest.Length)
			{
				charToTest = (char)byteArrayToTest[charCounter];
				itIsText &= (System.Char.IsLetterOrDigit(charToTest) |
					System.Char.IsWhiteSpace(charToTest) |
					System.Char.IsPunctuation(charToTest));
				charCounter++;
				retVal.Append(charToTest);
			}

			if (itIsText)
			{
				return retVal.ToString();
			}
			else
			{
				return "";
			}
		}

		private string GetTime(byte[] encodedTime, bool utcTime)
		{
			//Formats according to http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
			//We convert to 'Coordinated Universal Time' as described in http://www.w3.org/TR/xmlschema-2/#dateTime-canonical-repr
			int charCounter = 0;
			string retVal = "";

			if (utcTime)
			{
				if (encodedTime[0] < 0x35)
				{
					retVal = "20";
				}
				else
				{
					retVal = "19";
				}
			}
			else
			{
				retVal += (char)encodedTime[charCounter++];
				retVal += (char)encodedTime[charCounter++];
			}
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			retVal += "-";
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			retVal += "-";
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			retVal += "T";
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			retVal += ":";
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			retVal += ":";
			retVal += (char)encodedTime[charCounter++];
			retVal += (char)encodedTime[charCounter++];
			if (!utcTime)
			{
				while ((char)encodedTime[charCounter] != 'Z')
				{
					retVal += (char)encodedTime[charCounter++];
				}
			}
			retVal += "Z";

			return retVal;
		}

		private Asn1ItemData GetItemData(byte[] currentBytesToParse, bool throwErrors, ref long index)
		{
			int buffer;
			int buffer2;
			long lengthLength = 0;
			int lengthCounter;
			Asn1ItemData retVal;

			retVal = new Asn1ItemData();

			try
			{
				//Fetch the tag
				buffer = currentBytesToParse[index++];
				retVal.TagClass = (TagClasses)((buffer & TagClassMask) >> 6);
				retVal.TagConstructedFlag = (TagConstructed)((buffer & TagConstructedFlagMask) >> 5);
				retVal.TagNumber = (UniversalTags)(buffer & TagNumberMask);

				//Fetch the length
				retVal.BytesToParseLength = currentBytesToParse[index++];
				if ((retVal.BytesToParseLength & LEN_XTND) != 0)
				{ //We have a multiple byte length
					lengthLength = retVal.BytesToParseLength & LEN_MASK; //Strip bit
					if (lengthLength > 4)
					{
						throw new Exception("Bad length encountered: " + lengthLength.ToString() + " (index: " + index + ")");
					}
					if (lengthLength == 0)
					{
						throw new Exception("Parser can't deal with indefinite length (index: " + index + ")");
					}
					retVal.BytesToParseLength = 0;
					for (lengthCounter = 0; lengthCounter < lengthLength; lengthCounter++)
					{ 
						buffer2 = currentBytesToParse[index++];
						retVal.BytesToParseLength = (retVal.BytesToParseLength << 8) | (uint)buffer2;
					}
				}
				retVal.HeaderLength = 2 + lengthLength;

				//Fetch the raw data
				retVal.BytesToParse = new byte[retVal.BytesToParseLength];
				for (lengthCounter = 0; lengthCounter < retVal.BytesToParseLength; lengthCounter++)
				{
					retVal.BytesToParse[lengthCounter] = currentBytesToParse[index++];
				}

				retVal.TagName = retVal.TagClass.ToString() + "_" + retVal.TagConstructedFlag.ToString() + "_";
				if (retVal.TagClass == TagClasses.Universal)
				{
					retVal.TagName += retVal.TagNumber.ToString();
				}
				else
				{
					retVal.TagName += buffer.ToString("X2");
				}
			}
			catch (Exception exception)
			{
				if (throwErrors)
				{
					throw exception;
				}
				else
				{
					retVal = null;
				}
			}

			return retVal;
		}

		private void ParseAsn1Item(XmlNode currentXmlNode, byte[] currentBytesToParse, long index)
		{
			int buffer;
			int buffer2;
			int lengthCounter;
			XmlAttribute newXmlAttribute;
			XmlNode newChildXmlNode;
			XmlNode rawDataXmlNode;
			string valueBuffer;
			UInt64 integerBuffer;

			while (index < currentBytesToParse.Length)
			{
				Asn1ItemData asn1ItemData = this.GetItemData(currentBytesToParse, true, ref index);

				newChildXmlNode = currentXmlNode.OwnerDocument.CreateElement(asn1ItemData.TagName);

				newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Length");
				newXmlAttribute.Value = asn1ItemData.BytesToParseLength.ToString();
				newChildXmlNode.Attributes.Append(newXmlAttribute);
				rawDataXmlNode = currentXmlNode.OwnerDocument.CreateElement("RawData");
				rawDataXmlNode.InnerText = Convert.ToBase64String(asn1ItemData.BytesToParse);
				newChildXmlNode.AppendChild(rawDataXmlNode);
				currentXmlNode.AppendChild(newChildXmlNode);

				if (asn1ItemData.TagConstructedFlag == TagConstructed.Constructed)
				{ //Recurse
					long indexForNextRecursion = 0;
					this.ParseAsn1Item(newChildXmlNode, asn1ItemData.BytesToParse, indexForNextRecursion);
				}
				else
				{
					valueBuffer = "";
					if (asn1ItemData.TagClass == TagClasses.Universal)
					{
						switch (asn1ItemData.TagNumber)
						{
							case UniversalTags.Boolean:
								if (asn1ItemData.BytesToParse[0] != 0 && asn1ItemData.BytesToParse[0] != 0xFF)
								{
									throw new Exception("BOOLEAN containf wrong value (" + asn1ItemData.BytesToParse[0].ToString("X2") + ")");
								}
								else
								{
									if (asn1ItemData.BytesToParse[0] == 0xFF)
									{
										valueBuffer = "True";
									}
									else
									{
										valueBuffer = "False";
									}
								}
								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
								newXmlAttribute.Value = valueBuffer;
								newChildXmlNode.Attributes.Append(newXmlAttribute);
								break;
							case UniversalTags.Oid:
								if (asn1ItemData.BytesToParseLength > MAX_OID_SIZE)
								{
									throw new Exception("OID length (" + asn1ItemData.BytesToParseLength + ") > MAX_OID_SIZE");
								}
								//Format the OID
								buffer = asn1ItemData.BytesToParse[0]/40;
								buffer2 = asn1ItemData.BytesToParse[0]%40;
								if (buffer > 2)
								{//Some OID magic: shave of any excess (>2) of buffer and add to buffer2
									buffer2 += (buffer - 2)*40;
									buffer = 2;
								}
								valueBuffer = string.Format("{0}.{1}", buffer, buffer2);

								buffer = 0;
								for (lengthCounter = 1; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
								{
									buffer = (buffer << 7) | (asn1ItemData.BytesToParse[lengthCounter] & 0x7F);
									if ((asn1ItemData.BytesToParse[lengthCounter] & 0x80) == 0)
									{
										valueBuffer += string.Format(".{0}", buffer);
										buffer = 0;
									}
								}
								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
								newXmlAttribute.Value = valueBuffer;
								newChildXmlNode.Attributes.Append(newXmlAttribute);
								break;
							case UniversalTags.Integer:
							case UniversalTags.Enumerated:
								if (asn1ItemData.BytesToParseLength < 9)
								{
									integerBuffer = 0;
									for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
									{
										integerBuffer = (integerBuffer << 8) | asn1ItemData.BytesToParse[lengthCounter];
									}
									valueBuffer = integerBuffer.ToString();
								}
								else
								{
									for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
									{
										valueBuffer += asn1ItemData.BytesToParse[lengthCounter].ToString("X2") + " ";
									}
								}
								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
								newXmlAttribute.Value = valueBuffer;
								newChildXmlNode.Attributes.Append(newXmlAttribute);
								break;
							case UniversalTags.OctetString:
								long indexForNextRecursion = 0;
								
								Asn1ItemData probeAsn1ItemData = this.GetItemData(asn1ItemData.BytesToParse, false, ref indexForNextRecursion);
								if (probeAsn1ItemData != null)
								{
									if (probeAsn1ItemData.BytesToParseLength + probeAsn1ItemData.HeaderLength == asn1ItemData.BytesToParseLength)
									{
										indexForNextRecursion = 0;
										this.ParseAsn1Item(newChildXmlNode, asn1ItemData.BytesToParse, indexForNextRecursion);
									}
									else
									{
										for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
										{
											valueBuffer += asn1ItemData.BytesToParse[lengthCounter].ToString("X2") + " ";
										}
										newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
										newXmlAttribute.Value = valueBuffer;
										newChildXmlNode.Attributes.Append(newXmlAttribute);
									}
								}
								else
								{
									for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
									{
										valueBuffer += asn1ItemData.BytesToParse[lengthCounter].ToString("X2") + " ";
									}
									newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
									newXmlAttribute.Value = valueBuffer;
									newChildXmlNode.Attributes.Append(newXmlAttribute);
								}
								break;
							case UniversalTags.Utf8String:
								//TODO: Utf8String is not the same as PrintableString
							case UniversalTags.BmpString:
								//TODO: BmpString is not the same as PrintableString
							case UniversalTags.VisibleString:
								//TODO: VisibleString is not the same as PrintableString
							case UniversalTags.IA5String:
								//TODO: IA5String is not the same as PrintableString
							case UniversalTags.PrintableString:
								for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
								{
									valueBuffer += (char)asn1ItemData.BytesToParse[lengthCounter];
								}
								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
								newXmlAttribute.Value = valueBuffer;
								newChildXmlNode.Attributes.Append(newXmlAttribute);

								break;
							case UniversalTags.GeneralizedTime:
								if (asn1ItemData.BytesToParseLength < 15)
								{
									throw new Exception("Genralized time has to be at least 15 bytes long (" + asn1ItemData.BytesToParseLength.ToString() + ")");
								}
								else
								{
									valueBuffer = this.GetTime(asn1ItemData.BytesToParse, false);
									newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
									newXmlAttribute.Value = valueBuffer;
									newChildXmlNode.Attributes.Append(newXmlAttribute);
								}
								break;
							case UniversalTags.UtcTime:
								if (asn1ItemData.BytesToParseLength != 13)
								{
									throw new Exception("UTC time has to be 13 bytes long (" + asn1ItemData.BytesToParseLength.ToString() + ")");
								}
								else
								{
									valueBuffer = this.GetTime(asn1ItemData.BytesToParse, true);
									newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
									newXmlAttribute.Value = valueBuffer;
									newChildXmlNode.Attributes.Append(newXmlAttribute);
								}
								break;
							case UniversalTags.BitString:
								int unusedBits = asn1ItemData.BytesToParse[0];
								if (unusedBits < 0 || unusedBits > 7)
								{
									throw new Exception("Unused bits of bistring out of range [1-7] (" + unusedBits.ToString() + ")");
								}
								byte bitmask = 0x80;
								if (asn1ItemData.BytesToParseLength - 1 < 5)
								{ //Short enough to show bits
									for (lengthCounter = 1; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
									{
										if (lengthCounter != (asn1ItemData.BytesToParseLength - 1))
										{
											for (int bitCounter = 0; bitCounter < 8; bitCounter++)
											{
												if (((bitmask >> bitCounter) & asn1ItemData.BytesToParse[lengthCounter]) == 0)
												{
													valueBuffer = "0" + valueBuffer;
												}
												else
												{
													valueBuffer = "1" + valueBuffer;
												}
											}
										}
										else
										{
											for (int bitCounter = 0; bitCounter < (8 - unusedBits); bitCounter++)
											{
												if (((bitmask >> bitCounter) & asn1ItemData.BytesToParse[lengthCounter]) == 0)
												{
													valueBuffer = "0" + valueBuffer;
												}
												else
												{
													valueBuffer = "1" + valueBuffer;
												}
											}
										}
									}
								}
								else
								{ //Too long show as in hexadecimal representation
									for (lengthCounter = 1; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
									{
										valueBuffer += asn1ItemData.BytesToParse[lengthCounter].ToString("X2") + " ";
									}
								}
								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("UnusedBits");
								newXmlAttribute.Value = unusedBits.ToString();
								newChildXmlNode.Attributes.Append(newXmlAttribute);

								newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
								newXmlAttribute.Value = valueBuffer;
								newChildXmlNode.Attributes.Append(newXmlAttribute);
								break;
							default:
								if (asn1ItemData.BytesToParseLength > 0)
								{
									throw new Exception("Unparsed data encountered");
								}
								break;
						}
					}
					else
					{
						valueBuffer = this.CheckText(asn1ItemData.BytesToParse);
						if (valueBuffer == "")
						{
							for (lengthCounter = 0; lengthCounter < asn1ItemData.BytesToParseLength; lengthCounter++)
							{
								valueBuffer += asn1ItemData.BytesToParse[lengthCounter].ToString("X2") + " ";
							}
						}
						newXmlAttribute = currentXmlNode.OwnerDocument.CreateAttribute("Value");
						newXmlAttribute.Value = valueBuffer;
						newChildXmlNode.Attributes.Append(newXmlAttribute);
					}
				}
			}
		}

		public void ParseAsn1(byte[] bytesToParse)
		{
			long bytesToParseIndex;
			XmlDocument newXmlDocument;

			bytesToParseIndex = 0;
			newXmlDocument = new XmlDocument();
			this.parseTree = newXmlDocument.CreateElement("Asn1Root");
			this.ParseAsn1Item(this.parseTree, bytesToParse, bytesToParseIndex);
		}
	}

	public class Asn1ItemData
	{
		private TagClasses tagClass;
		private TagConstructed tagConstructedFlag;
		private UniversalTags tagNumber;
		private string tagName;
		private long headerLength;
		private long length;
		private byte[] bytesToParse;
		
		public TagClasses TagClass
		{
			get
			{
				return this.tagClass;
			}
			set
			{
				this.tagClass = value;
			}
		}

		public TagConstructed TagConstructedFlag
		{
			get
			{
				return this.tagConstructedFlag;
			}
			set
			{
				this.tagConstructedFlag = value;
			}
		}

		public UniversalTags TagNumber
		{
			get
			{
				return this.tagNumber;
			}
			set
			{
				this.tagNumber = value;
			}
		}

		public string TagName
		{
			get
			{
				return this.tagName;
			}
			set
			{
				this.tagName = value;
			}
		}

		public long HeaderLength
		{
			get
			{
				return this.headerLength;
			}
			set
			{
				this.headerLength = value;
			}
		}

		public long BytesToParseLength
		{
			get
			{
				return this.length;
			}
			set
			{
				this.length = value;
			}
		}

		public byte[] BytesToParse
		{
			get
			{
				return this.bytesToParse;
			}
			set
			{
				this.bytesToParse = value;
			}
		}
	}

	public enum TagClasses
	{
		Universal = 0,
		Application = 1,
		ContextSpecific = 2,
		Private = 3
	}

	public enum TagConstructed
	{
		Primitive = 0,
		Constructed = 1
	}

	public enum UniversalTags : int
	{
		Eoc					= 0x00, //0: End-of-contents octets
		Boolean				= 0x01, //1: Boolean
		Integer				= 0x02, //2: Integer
		BitString			= 0x03, //2: Bit string
		OctetString			= 0x04, //4: Byte string
		NullTag				= 0x05, //5: Null
		Oid					= 0x06, //6: Object Identifier
		ObjDescriptor		= 0x07, //7: Object Descriptor
		External			= 0x08, //8: External
		Real				= 0x09, //9: Real
		Enumerated			= 0x0A, //10: Enumerated
		Embedded_Pdv		= 0x0B, //11: Embedded Presentation Data Value
		Utf8String			= 0x0C, //12: UTF8 string
		Sequence			= 0x10, //16: Sequence/sequence of
		Set					= 0x11, //17: Set/set of
		NumericString		= 0x12, //18: Numeric string
		PrintableString		= 0x13, //19: Printable string (ASCII subset)
		T61String			= 0x14, //20: T61/Teletex string
		VideotexString		= 0x15, //21: Videotex string
		IA5String			= 0x16, //22: IA5/ASCII string
		UtcTime				= 0x17, //23: UTC time
		GeneralizedTime		= 0x18, //24: Generalized time
		GraphicString		= 0x19, //25: Graphic string
		VisibleString		= 0x1A, //26: Visible string (ASCII subset)
		GeneralString		= 0x1B, //27: General string
		UniversalString		= 0x1C, //28: Universal string
		BmpString			= 0x1E, //30: Basic Multilingual Plane/Unicode string
	}
}
