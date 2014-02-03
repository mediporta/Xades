// XMLRenderTree.cs
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
using System.Xml;
using System.Windows.Forms;

namespace Microsoft.Xades.Test
{
	/// <summary>
	/// Control to render XmlNodes
	/// </summary>
	public class XmlRenderTree : TreeView
	{
		/// <summary>
		/// Default constructor
		/// </summary>
		public XmlRenderTree()
		{
		}

		public void RenderXmlNode(XmlNode xmlNode)
		{
			this.SuspendLayout();
			this.Visible = false;
			this.Nodes.Clear();
			this.RenderLevel(xmlNode);
			this.Visible = true;
			this.ResumeLayout(false);
		}

		private string GetText(XmlNode xmlNode)
		{
			string retVal;

			retVal = "<" + xmlNode.LocalName;
			if (xmlNode.Attributes != null)
			{
				foreach (XmlAttribute xmlAttribute in xmlNode.Attributes)
				{
					retVal += " " + xmlAttribute.LocalName + "=\"" + xmlAttribute.Value + "\"";
				}
			}
			retVal += ">";
			if (xmlNode is XmlText)
			{
				retVal += xmlNode.InnerText + "</" + xmlNode.LocalName + ">";
			}

			return retVal;
		}

		private void RenderLevel(XmlNode xmlNode)
		{
			TreeNode newTreeNode;

			newTreeNode = new TreeNode(this.GetText(xmlNode));
			if (this.SelectedNode == null)
			{
				this.Nodes.Add(newTreeNode);
			}
			else
			{
				this.SelectedNode.Nodes.Add(newTreeNode);
			}
			foreach (XmlNode childXmlNode in xmlNode)
			{
				if (!(childXmlNode is XmlWhitespace))
				{
					this.SelectedNode = newTreeNode;
					this.RenderLevel(childXmlNode);
					if (childXmlNode is XmlText)
					{
						newTreeNode.Collapse();
					}
					else
					{
						newTreeNode.Expand();
					}
				}
			}
		}
	}
}
