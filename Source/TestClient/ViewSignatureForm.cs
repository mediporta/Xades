// ViewSignatureForm.cs
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
using Microsoft.Xades;
using System.Xml;

namespace Microsoft.Xades.Test
{
	/// <summary>
	/// Summary description for ViewCertificateForm.
	/// </summary>
	public class ViewSignatureForm : System.Windows.Forms.Form
	{
		private XmlElement bufferedXmlElement;

        private Microsoft.Xades.Test.XmlRenderTree signatureXmlRenderTree;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.Label signatureStandardLabel;
		private System.Windows.Forms.Button saveSignatureButton;
		private System.Windows.Forms.SaveFileDialog saveFileDialog;
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.Container components = null;

		public ViewSignatureForm()
		{
			//
			// Required for Windows Form Designer support
			//
			this.InitializeComponent();
		}

		/// <summary>
		/// Clean up any resources being used.
		/// </summary>
		/// <param name="disposing">Flag indicating if already disposing</param>
		protected override void Dispose(bool disposing)
		{
			if (disposing)
			{
				if (this.components != null)
				{
					this.components.Dispose();
				}
			}
			base.Dispose(disposing);
		}

		#region Windows Form Designer generated code
		/// <summary>
		/// Required method for Designer support - do not modify
		/// the contents of this method with the code editor.
		/// </summary>
		private void InitializeComponent()
		{
            this.signatureXmlRenderTree = new Microsoft.Xades.Test.XmlRenderTree();
            this.label2 = new System.Windows.Forms.Label();
            this.signatureStandardLabel = new System.Windows.Forms.Label();
            this.saveSignatureButton = new System.Windows.Forms.Button();
            this.saveFileDialog = new System.Windows.Forms.SaveFileDialog();
            this.SuspendLayout();
            // 
            // signatureXmlRenderTree
            // 
            this.signatureXmlRenderTree.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureXmlRenderTree.Location = new System.Drawing.Point(0, 49);
            this.signatureXmlRenderTree.Name = "signatureXmlRenderTree";
            this.signatureXmlRenderTree.Size = new System.Drawing.Size(776, 599);
            this.signatureXmlRenderTree.TabIndex = 5;
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(8, 17);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(104, 16);
            this.label2.TabIndex = 6;
            this.label2.Text = "Signature standard:";
            // 
            // signatureStandardLabel
            // 
            this.signatureStandardLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.signatureStandardLabel.Location = new System.Drawing.Point(120, 17);
            this.signatureStandardLabel.Name = "signatureStandardLabel";
            this.signatureStandardLabel.Size = new System.Drawing.Size(368, 16);
            this.signatureStandardLabel.TabIndex = 7;
            // 
            // saveSignatureButton
            // 
            this.saveSignatureButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.saveSignatureButton.Location = new System.Drawing.Point(655, 8);
            this.saveSignatureButton.Name = "saveSignatureButton";
            this.saveSignatureButton.Size = new System.Drawing.Size(113, 35);
            this.saveSignatureButton.TabIndex = 8;
            this.saveSignatureButton.Text = "Save signature...";
            this.saveSignatureButton.Click += new System.EventHandler(this.saveSignatureButton_Click);
            // 
            // saveFileDialog
            // 
            this.saveFileDialog.DefaultExt = "xml";
            // 
            // ViewSignatureForm
            // 
            this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            this.ClientSize = new System.Drawing.Size(776, 646);
            this.Controls.Add(this.saveSignatureButton);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.signatureStandardLabel);
            this.Controls.Add(this.signatureXmlRenderTree);
            this.Name = "ViewSignatureForm";
            this.Text = "Signature Viewer";
            this.ResumeLayout(false);

		}
		#endregion

		public void ShowSignature(KnownSignatureStandard signatureStandard, XmlElement xmlElementToShow)
		{
			this.bufferedXmlElement = xmlElementToShow;
			this.signatureStandardLabel.Text = signatureStandard.ToString();
			this.signatureXmlRenderTree.RenderXmlNode(xmlElementToShow);
		}

		private void saveSignatureButton_Click(object sender, System.EventArgs e)
		{
			DialogResult dialogResult;

			dialogResult = this.saveFileDialog.ShowDialog();
			if (dialogResult == DialogResult.OK)
			{
				XmlDocument xmlDocument = new XmlDocument();
				xmlDocument.PreserveWhitespace = true; //Needed
				xmlDocument.LoadXml(this.bufferedXmlElement.OuterXml);
				xmlDocument.Save(this.saveFileDialog.FileName);
			}
		}
	}
}
