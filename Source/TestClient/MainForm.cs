// MainForm.cs
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
using System.IO;
using System.Drawing;
using System.Collections;
using System.ComponentModel;
using System.Windows.Forms;
using System.Data;
using System.Xml;
using System.Xml.Schema;
using System.Xml.Serialization;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Xades;
using System.Net;
using System.Reflection;
using System.Text;

namespace Microsoft.Xades.Test
{
	/// <summary>
	/// Main form of the XAdES demo application
	/// </summary>
	public class MainForm : System.Windows.Forms.Form
	{
		private string tempFile;
        private X509Certificate2 Certificate;
        private X509Chain Chain;
		private XmlDocument envelopedSignatureXmlDocument;
		private Microsoft.Xades.XadesSignedXml xadesSignedXml;
		private int documentDataObjectCounter;

		private System.Windows.Forms.OpenFileDialog openFileDialog;
		private System.Windows.Forms.GroupBox groupBox1;
		private System.Windows.Forms.Label label1;
		private System.Windows.Forms.TextBox signatureFileToReadTextBox;
		private System.Windows.Forms.Button browseForFileToReadButton;
		private System.Windows.Forms.Label signatureTypeLabel;
		private System.Windows.Forms.TabControl tabControl1;
		private System.Windows.Forms.TabPage tabPage1;
		private System.Windows.Forms.TabPage tabPage2;
		private System.Windows.Forms.RadioButton externalDocumentRadioButton;
		private System.Windows.Forms.RadioButton includedXmlRadioButton;
		private System.Windows.Forms.TextBox includedXmltextBox;
		private System.Windows.Forms.TextBox externalDocumentUrlTextBox;
		private System.Windows.Forms.Button addReferenceButton;
		private System.Windows.Forms.Label label4;
		private System.Windows.Forms.Label certificateInfoIssuedLabel;
		private System.Windows.Forms.Label label5;
		private System.Windows.Forms.Label certificateInfoIssuerLabel;
		private System.Windows.Forms.TabControl tabControl2;
		private System.Windows.Forms.TabPage tabPage3;
		private System.Windows.Forms.TabPage tabPage4;
		private System.Windows.Forms.TabPage tabPage5;
		private System.Windows.Forms.Label label3;
		private System.Windows.Forms.Button addXadesInfoButton;
		private System.Windows.Forms.Label label6;
		private System.Windows.Forms.TextBox signatureCityTextBox;
		private System.Windows.Forms.Label label7;
		private System.Windows.Forms.TextBox signatureStateOrProvinceTextBox;
		private System.Windows.Forms.Label label8;
		private System.Windows.Forms.TextBox signaturePostalCodeTextBox;
		private System.Windows.Forms.Label label9;
		private System.Windows.Forms.TextBox signatureCountryNameTextBox;
		private System.Windows.Forms.TabPage tabPage7;
		private System.Windows.Forms.Button checkSignatureButton;
		private System.Windows.Forms.Label checkSignatureLabel;
		private System.Windows.Forms.GroupBox groupBox2;
		private System.Windows.Forms.CheckBox includeSignatureProductionPlaceCheckBox;
		private System.Windows.Forms.GroupBox groupBox5;
		private System.Windows.Forms.Label label10;
		private System.Windows.Forms.Label label11;
		private System.Windows.Forms.Label label12;
		private System.Windows.Forms.Label issuerSerialLabel;
		private System.Windows.Forms.Label digestMethodLabel;
		private System.Windows.Forms.Label digestValueLabel;
		private System.Windows.Forms.Label label13;
		private System.Windows.Forms.Label issuerNameLabel;
		private System.Windows.Forms.GroupBox groupBox6;
		private System.Windows.Forms.Label label14;
		private System.Windows.Forms.Label label15;
		private System.Windows.Forms.GroupBox groupBox7;
		private System.Windows.Forms.Label label16;
		private System.Windows.Forms.Label label17;
		private System.Windows.Forms.TabPage tabPage6;
		private System.Windows.Forms.GroupBox groupBox9;
		private System.Windows.Forms.CheckBox includeSignerRoleCheckBox;
		private System.Windows.Forms.Label label18;
		private System.Windows.Forms.TextBox claimedRoleTextBox;
		private System.Windows.Forms.CheckBox readOnlyNoCheckcheckBox;
		private System.Windows.Forms.GroupBox groupBox10;
		private System.Windows.Forms.CheckBox includeCommitmentTypeIndicationCheckBox;
		private System.Windows.Forms.Label label19;
		private System.Windows.Forms.TextBox commitmentTypeIndicationIdTextBox;
		private System.Windows.Forms.Label label20;
		private System.Windows.Forms.Label label21;
		private System.Windows.Forms.Label label22;
		private System.Windows.Forms.TextBox commitmentTypeIdentifierURITextBox;
		private System.Windows.Forms.Label label23;
		private System.Windows.Forms.TabPage tabPage8;
		private System.Windows.Forms.GroupBox groupBox11;
		private System.Windows.Forms.CheckBox includeDataObjectFormatCheckBox;
		private System.Windows.Forms.Label label24;
		private System.Windows.Forms.Label label25;
		private System.Windows.Forms.Label label26;
		private System.Windows.Forms.TextBox dataObjectDescriptionTextBox;
		private System.Windows.Forms.TextBox dataObjectFormatMimetypeTextBox;
        private System.Windows.Forms.TextBox dataObjectReferenceTextBox;
		private System.Windows.Forms.GroupBox groupBox14;
		private System.Windows.Forms.GroupBox groupBox15;
		private System.Windows.Forms.CheckBox includeKeyValueCheckBox;
		private System.Windows.Forms.TextBox signingTimeTextBox;
        private Microsoft.Xades.Test.XmlRenderTree verifyXmlRenderTree;
		private System.Windows.Forms.TabPage tabPage9;
		private System.Windows.Forms.GroupBox groupBox4;
		private System.Windows.Forms.CheckBox includeCertificateChainCheckBox;
		private System.Windows.Forms.TabPage tabPage10;
		private System.Windows.Forms.GroupBox groupBox8;
		private System.Windows.Forms.TextBox envelopingDocumentTextBox;
		private System.Windows.Forms.GroupBox groupBox13;
		private System.Windows.Forms.Label label28;
		private System.Windows.Forms.TextBox signatureIdTextBox;
		private System.Windows.Forms.Label label29;
		private System.Windows.Forms.TextBox objectIdPrefixTextBox;
		private System.Windows.Forms.Label label30;
		private System.Windows.Forms.TextBox tsaUriTextBox;
		private System.Windows.Forms.CheckBox tsaCertificateInResponseCheckBox;
		private System.Windows.Forms.ComboBox commitmentTypeIndicatorQualifierComboBox;
		private System.Windows.Forms.RadioButton envelopedSignatureRadioButton;
		private System.Windows.Forms.Button envelopedSignatureDocumentLocateButton;
		private System.Windows.Forms.Button computeSignatureButton;
		private System.Windows.Forms.Label label31;
		private System.Windows.Forms.Label nextObjectIdSuffixLabel;
		private System.Windows.Forms.CheckBox newSignatureCheckBox;
		private System.Windows.Forms.Button requestTimeStampButton;
		private System.Windows.Forms.Button injectXadesCInformationButton;
		private System.Windows.Forms.CheckBox includeCrlCheckBox;
		private System.Windows.Forms.Label label32;
		private System.Windows.Forms.TextBox crlFileTextBox;
		private System.Windows.Forms.Button crlFileLocateButton;
		private System.Windows.Forms.Button selectCertificateButton;
        private System.Windows.Forms.Label checkExplanationLabel;
		private System.Windows.Forms.Label label2;
		private System.Windows.Forms.TextBox signatureValueIdTextBox;
		private System.Windows.Forms.TabPage tabPage11;
		private System.Windows.Forms.GroupBox groupBox3;
		private System.Windows.Forms.RadioButton sigAndRefsTimeStampRadioButton;
		private System.Windows.Forms.RadioButton refsOnlyTimeStampRadioButton;
		private System.Windows.Forms.Button injectXadesXInformationButton;
		private System.Windows.Forms.TextBox signatureTimeStampIdTextBox;
		private System.Windows.Forms.Label label27;
		private System.Windows.Forms.Label label33;
		private System.Windows.Forms.TextBox completeCertificateRefsTextBox;
		private System.Windows.Forms.Label label34;
		private System.Windows.Forms.TextBox completeRevocationRefsIdTextBox;
		private System.Windows.Forms.TextBox xadesXTimeStampIdTextBox;
		private System.Windows.Forms.Label label35;
		private System.Windows.Forms.TabPage tabPage12;
		private System.Windows.Forms.GroupBox groupBox17;
		private System.Windows.Forms.Button injectXadesXLInformationButton;
		private System.Windows.Forms.Label label36;
		private System.Windows.Forms.TextBox certificateValuesIdTextBox;
		private System.Windows.Forms.TextBox revocationValuesIdTextBox;
		private System.Windows.Forms.Label label37;
		private System.Windows.Forms.CheckBox includeCertificateValuesCheckBox;
		private System.Windows.Forms.CheckBox includeRevocationValuesCheckBox;
		private System.Windows.Forms.CheckBox verify008000CheckBox;
		private System.Windows.Forms.CheckBox verify000001CheckBox;
		private System.Windows.Forms.CheckBox verify004000CheckBox;
		private System.Windows.Forms.CheckBox verify000020CheckBox;
		private System.Windows.Forms.CheckBox verify000200CheckBox;
		private System.Windows.Forms.CheckBox verify000040CheckBox;
		private System.Windows.Forms.CheckBox verify000400CheckBox;
		private System.Windows.Forms.CheckBox verify000080CheckBox;
		private System.Windows.Forms.CheckBox verify000004CheckBox;
		private System.Windows.Forms.CheckBox verify002000CheckBox;
		private System.Windows.Forms.CheckBox verify001000CheckBox;
		private System.Windows.Forms.CheckBox verify000100CheckBox;
		private System.Windows.Forms.CheckBox verify000800CheckBox;
		private System.Windows.Forms.CheckBox verify000010CheckBox;
		private System.Windows.Forms.CheckBox verify000002CheckBox;
		private System.Windows.Forms.CheckBox verify000008CheckBox;
		private System.Windows.Forms.CheckBox verify010000CheckBox;
		private System.Windows.Forms.CheckBox verify020000CheckBox;
		private System.Windows.Forms.CheckBox verify040000CheckBox;
		private System.Windows.Forms.GroupBox checkSelectionGroupBox;
        private Button viewCertificateButton;
        private Button addCounterSignatureButton;
		/// <summary>
		/// Required designer variable.
		/// </summary>
		private System.ComponentModel.Container components = null;

		/// <summary>
		/// Contructor of the Form
		/// </summary>
		public MainForm()
		{
			// Required for Windows Form Designer support
			this.InitializeComponent();

			this.tempFile = System.IO.Path.GetTempPath() + "TempSignature.xml";
			this.signingTimeTextBox.Text = DateTime.Now.ToString("s");
			this.documentDataObjectCounter = 1;
			this.nextObjectIdSuffixLabel.Text = this.documentDataObjectCounter.ToString();
			this.Chain = null;
		}

		/// <summary>
		/// Clean up any resources being used
		/// </summary>
		/// <param name="disposing">Flag indicating if disposing going on</param>
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
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.browseForFileToReadButton = new System.Windows.Forms.Button();
            this.signatureFileToReadTextBox = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.checkSignatureLabel = new System.Windows.Forms.Label();
            this.checkSignatureButton = new System.Windows.Forms.Button();
            this.signatureTypeLabel = new System.Windows.Forms.Label();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.tabPage2 = new System.Windows.Forms.TabPage();
            this.tabControl2 = new System.Windows.Forms.TabControl();
            this.tabPage4 = new System.Windows.Forms.TabPage();
            this.newSignatureCheckBox = new System.Windows.Forms.CheckBox();
            this.nextObjectIdSuffixLabel = new System.Windows.Forms.Label();
            this.label31 = new System.Windows.Forms.Label();
            this.envelopedSignatureDocumentLocateButton = new System.Windows.Forms.Button();
            this.envelopingDocumentTextBox = new System.Windows.Forms.TextBox();
            this.envelopedSignatureRadioButton = new System.Windows.Forms.RadioButton();
            this.externalDocumentRadioButton = new System.Windows.Forms.RadioButton();
            this.includedXmlRadioButton = new System.Windows.Forms.RadioButton();
            this.externalDocumentUrlTextBox = new System.Windows.Forms.TextBox();
            this.addReferenceButton = new System.Windows.Forms.Button();
            this.includedXmltextBox = new System.Windows.Forms.TextBox();
            this.objectIdPrefixTextBox = new System.Windows.Forms.TextBox();
            this.label29 = new System.Windows.Forms.Label();
            this.tabPage3 = new System.Windows.Forms.TabPage();
            this.groupBox15 = new System.Windows.Forms.GroupBox();
            this.includeKeyValueCheckBox = new System.Windows.Forms.CheckBox();
            this.selectCertificateButton = new System.Windows.Forms.Button();
            this.groupBox14 = new System.Windows.Forms.GroupBox();
            this.viewCertificateButton = new System.Windows.Forms.Button();
            this.label4 = new System.Windows.Forms.Label();
            this.certificateInfoIssuedLabel = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.certificateInfoIssuerLabel = new System.Windows.Forms.Label();
            this.tabPage5 = new System.Windows.Forms.TabPage();
            this.groupBox13 = new System.Windows.Forms.GroupBox();
            this.signatureValueIdTextBox = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.signatureIdTextBox = new System.Windows.Forms.TextBox();
            this.label28 = new System.Windows.Forms.Label();
            this.signingTimeTextBox = new System.Windows.Forms.TextBox();
            this.label3 = new System.Windows.Forms.Label();
            this.groupBox7 = new System.Windows.Forms.GroupBox();
            this.label17 = new System.Windows.Forms.Label();
            this.label16 = new System.Windows.Forms.Label();
            this.groupBox5 = new System.Windows.Forms.GroupBox();
            this.issuerNameLabel = new System.Windows.Forms.Label();
            this.label13 = new System.Windows.Forms.Label();
            this.digestValueLabel = new System.Windows.Forms.Label();
            this.digestMethodLabel = new System.Windows.Forms.Label();
            this.issuerSerialLabel = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.label11 = new System.Windows.Forms.Label();
            this.label10 = new System.Windows.Forms.Label();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.includeSignatureProductionPlaceCheckBox = new System.Windows.Forms.CheckBox();
            this.signatureCountryNameTextBox = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.signaturePostalCodeTextBox = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.signatureStateOrProvinceTextBox = new System.Windows.Forms.TextBox();
            this.label7 = new System.Windows.Forms.Label();
            this.signatureCityTextBox = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.tabPage6 = new System.Windows.Forms.TabPage();
            this.groupBox10 = new System.Windows.Forms.GroupBox();
            this.commitmentTypeIndicatorQualifierComboBox = new System.Windows.Forms.ComboBox();
            this.label23 = new System.Windows.Forms.Label();
            this.commitmentTypeIdentifierURITextBox = new System.Windows.Forms.TextBox();
            this.label22 = new System.Windows.Forms.Label();
            this.label21 = new System.Windows.Forms.Label();
            this.label20 = new System.Windows.Forms.Label();
            this.commitmentTypeIndicationIdTextBox = new System.Windows.Forms.TextBox();
            this.label19 = new System.Windows.Forms.Label();
            this.includeCommitmentTypeIndicationCheckBox = new System.Windows.Forms.CheckBox();
            this.groupBox9 = new System.Windows.Forms.GroupBox();
            this.label18 = new System.Windows.Forms.Label();
            this.claimedRoleTextBox = new System.Windows.Forms.TextBox();
            this.includeSignerRoleCheckBox = new System.Windows.Forms.CheckBox();
            this.groupBox11 = new System.Windows.Forms.GroupBox();
            this.dataObjectReferenceTextBox = new System.Windows.Forms.TextBox();
            this.dataObjectFormatMimetypeTextBox = new System.Windows.Forms.TextBox();
            this.dataObjectDescriptionTextBox = new System.Windows.Forms.TextBox();
            this.label26 = new System.Windows.Forms.Label();
            this.label25 = new System.Windows.Forms.Label();
            this.label24 = new System.Windows.Forms.Label();
            this.includeDataObjectFormatCheckBox = new System.Windows.Forms.CheckBox();
            this.addXadesInfoButton = new System.Windows.Forms.Button();
            this.tabPage7 = new System.Windows.Forms.TabPage();
            this.computeSignatureButton = new System.Windows.Forms.Button();
            this.tabPage8 = new System.Windows.Forms.TabPage();
            this.addCounterSignatureButton = new System.Windows.Forms.Button();
            this.tabPage10 = new System.Windows.Forms.TabPage();
            this.groupBox8 = new System.Windows.Forms.GroupBox();
            this.label27 = new System.Windows.Forms.Label();
            this.signatureTimeStampIdTextBox = new System.Windows.Forms.TextBox();
            this.requestTimeStampButton = new System.Windows.Forms.Button();
            this.tsaCertificateInResponseCheckBox = new System.Windows.Forms.CheckBox();
            this.tsaUriTextBox = new System.Windows.Forms.TextBox();
            this.label30 = new System.Windows.Forms.Label();
            this.tabPage9 = new System.Windows.Forms.TabPage();
            this.groupBox4 = new System.Windows.Forms.GroupBox();
            this.completeRevocationRefsIdTextBox = new System.Windows.Forms.TextBox();
            this.label34 = new System.Windows.Forms.Label();
            this.completeCertificateRefsTextBox = new System.Windows.Forms.TextBox();
            this.label33 = new System.Windows.Forms.Label();
            this.crlFileLocateButton = new System.Windows.Forms.Button();
            this.crlFileTextBox = new System.Windows.Forms.TextBox();
            this.label32 = new System.Windows.Forms.Label();
            this.includeCrlCheckBox = new System.Windows.Forms.CheckBox();
            this.injectXadesCInformationButton = new System.Windows.Forms.Button();
            this.includeCertificateChainCheckBox = new System.Windows.Forms.CheckBox();
            this.tabPage11 = new System.Windows.Forms.TabPage();
            this.groupBox3 = new System.Windows.Forms.GroupBox();
            this.label35 = new System.Windows.Forms.Label();
            this.xadesXTimeStampIdTextBox = new System.Windows.Forms.TextBox();
            this.injectXadesXInformationButton = new System.Windows.Forms.Button();
            this.refsOnlyTimeStampRadioButton = new System.Windows.Forms.RadioButton();
            this.sigAndRefsTimeStampRadioButton = new System.Windows.Forms.RadioButton();
            this.tabPage12 = new System.Windows.Forms.TabPage();
            this.groupBox17 = new System.Windows.Forms.GroupBox();
            this.includeRevocationValuesCheckBox = new System.Windows.Forms.CheckBox();
            this.includeCertificateValuesCheckBox = new System.Windows.Forms.CheckBox();
            this.label37 = new System.Windows.Forms.Label();
            this.revocationValuesIdTextBox = new System.Windows.Forms.TextBox();
            this.certificateValuesIdTextBox = new System.Windows.Forms.TextBox();
            this.label36 = new System.Windows.Forms.Label();
            this.injectXadesXLInformationButton = new System.Windows.Forms.Button();
            this.tabPage1 = new System.Windows.Forms.TabPage();
            this.groupBox6 = new System.Windows.Forms.GroupBox();
            this.checkSelectionGroupBox = new System.Windows.Forms.GroupBox();
            this.verify040000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify020000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify010000CheckBox = new System.Windows.Forms.CheckBox();
            this.checkExplanationLabel = new System.Windows.Forms.Label();
            this.verify000001CheckBox = new System.Windows.Forms.CheckBox();
            this.verify004000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000020CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000200CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000040CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000400CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000080CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000004CheckBox = new System.Windows.Forms.CheckBox();
            this.verify002000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify001000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000100CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000800CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000010CheckBox = new System.Windows.Forms.CheckBox();
            this.verify008000CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000002CheckBox = new System.Windows.Forms.CheckBox();
            this.verify000008CheckBox = new System.Windows.Forms.CheckBox();
            this.verifyXmlRenderTree = new Microsoft.Xades.Test.XmlRenderTree();
            this.readOnlyNoCheckcheckBox = new System.Windows.Forms.CheckBox();
            this.label15 = new System.Windows.Forms.Label();
            this.label14 = new System.Windows.Forms.Label();
            this.groupBox1.SuspendLayout();
            this.tabControl1.SuspendLayout();
            this.tabPage2.SuspendLayout();
            this.tabControl2.SuspendLayout();
            this.tabPage4.SuspendLayout();
            this.tabPage3.SuspendLayout();
            this.groupBox15.SuspendLayout();
            this.groupBox14.SuspendLayout();
            this.tabPage5.SuspendLayout();
            this.groupBox13.SuspendLayout();
            this.groupBox7.SuspendLayout();
            this.groupBox5.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.tabPage6.SuspendLayout();
            this.groupBox10.SuspendLayout();
            this.groupBox9.SuspendLayout();
            this.groupBox11.SuspendLayout();
            this.tabPage7.SuspendLayout();
            this.tabPage8.SuspendLayout();
            this.tabPage10.SuspendLayout();
            this.groupBox8.SuspendLayout();
            this.tabPage9.SuspendLayout();
            this.groupBox4.SuspendLayout();
            this.tabPage11.SuspendLayout();
            this.groupBox3.SuspendLayout();
            this.tabPage12.SuspendLayout();
            this.groupBox17.SuspendLayout();
            this.tabPage1.SuspendLayout();
            this.groupBox6.SuspendLayout();
            this.checkSelectionGroupBox.SuspendLayout();
            this.SuspendLayout();
            // 
            // groupBox1
            // 
            this.groupBox1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox1.Controls.Add(this.browseForFileToReadButton);
            this.groupBox1.Controls.Add(this.signatureFileToReadTextBox);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Location = new System.Drawing.Point(8, 8);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(696, 48);
            this.groupBox1.TabIndex = 2;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Signature file to read";
            // 
            // browseForFileToReadButton
            // 
            this.browseForFileToReadButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.browseForFileToReadButton.Location = new System.Drawing.Point(659, 15);
            this.browseForFileToReadButton.Name = "browseForFileToReadButton";
            this.browseForFileToReadButton.Size = new System.Drawing.Size(24, 23);
            this.browseForFileToReadButton.TabIndex = 4;
            this.browseForFileToReadButton.Text = "...";
            this.browseForFileToReadButton.Click += new System.EventHandler(this.browseForFileToReadButton_Click);
            // 
            // signatureFileToReadTextBox
            // 
            this.signatureFileToReadTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureFileToReadTextBox.Location = new System.Drawing.Point(96, 17);
            this.signatureFileToReadTextBox.Name = "signatureFileToReadTextBox";
            this.signatureFileToReadTextBox.Size = new System.Drawing.Size(560, 20);
            this.signatureFileToReadTextBox.TabIndex = 3;
            // 
            // label1
            // 
            this.label1.Location = new System.Drawing.Point(16, 20);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(80, 16);
            this.label1.TabIndex = 2;
            this.label1.Text = "Signature File:";
            // 
            // checkSignatureLabel
            // 
            this.checkSignatureLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.checkSignatureLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.checkSignatureLabel.ForeColor = System.Drawing.SystemColors.ControlText;
            this.checkSignatureLabel.Location = new System.Drawing.Point(144, 72);
            this.checkSignatureLabel.Name = "checkSignatureLabel";
            this.checkSignatureLabel.Size = new System.Drawing.Size(80, 24);
            this.checkSignatureLabel.TabIndex = 10;
            // 
            // checkSignatureButton
            // 
            this.checkSignatureButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.checkSignatureButton.Location = new System.Drawing.Point(614, 16);
            this.checkSignatureButton.Name = "checkSignatureButton";
            this.checkSignatureButton.Size = new System.Drawing.Size(74, 72);
            this.checkSignatureButton.TabIndex = 9;
            this.checkSignatureButton.Text = "Check XAdES Signature";
            this.checkSignatureButton.Click += new System.EventHandler(this.checkSignatureButton_Click);
            // 
            // signatureTypeLabel
            // 
            this.signatureTypeLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureTypeLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 9.75F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.signatureTypeLabel.ForeColor = System.Drawing.SystemColors.ControlText;
            this.signatureTypeLabel.Location = new System.Drawing.Point(144, 48);
            this.signatureTypeLabel.Name = "signatureTypeLabel";
            this.signatureTypeLabel.Size = new System.Drawing.Size(80, 24);
            this.signatureTypeLabel.TabIndex = 8;
            // 
            // tabControl1
            // 
            this.tabControl1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.tabControl1.Controls.Add(this.tabPage2);
            this.tabControl1.Controls.Add(this.tabPage1);
            this.tabControl1.Location = new System.Drawing.Point(8, 8);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(720, 568);
            this.tabControl1.TabIndex = 9;
            // 
            // tabPage2
            // 
            this.tabPage2.Controls.Add(this.tabControl2);
            this.tabPage2.Location = new System.Drawing.Point(4, 22);
            this.tabPage2.Name = "tabPage2";
            this.tabPage2.Size = new System.Drawing.Size(712, 542);
            this.tabPage2.TabIndex = 1;
            this.tabPage2.Text = "Create signature";
            // 
            // tabControl2
            // 
            this.tabControl2.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.tabControl2.Controls.Add(this.tabPage4);
            this.tabControl2.Controls.Add(this.tabPage3);
            this.tabControl2.Controls.Add(this.tabPage5);
            this.tabControl2.Controls.Add(this.tabPage6);
            this.tabControl2.Controls.Add(this.tabPage7);
            this.tabControl2.Controls.Add(this.tabPage8);
            this.tabControl2.Controls.Add(this.tabPage10);
            this.tabControl2.Controls.Add(this.tabPage9);
            this.tabControl2.Controls.Add(this.tabPage11);
            this.tabControl2.Controls.Add(this.tabPage12);
            this.tabControl2.Location = new System.Drawing.Point(8, 8);
            this.tabControl2.Name = "tabControl2";
            this.tabControl2.SelectedIndex = 0;
            this.tabControl2.Size = new System.Drawing.Size(696, 528);
            this.tabControl2.TabIndex = 4;
            // 
            // tabPage4
            // 
            this.tabPage4.Controls.Add(this.newSignatureCheckBox);
            this.tabPage4.Controls.Add(this.nextObjectIdSuffixLabel);
            this.tabPage4.Controls.Add(this.label31);
            this.tabPage4.Controls.Add(this.envelopedSignatureDocumentLocateButton);
            this.tabPage4.Controls.Add(this.envelopingDocumentTextBox);
            this.tabPage4.Controls.Add(this.envelopedSignatureRadioButton);
            this.tabPage4.Controls.Add(this.externalDocumentRadioButton);
            this.tabPage4.Controls.Add(this.includedXmlRadioButton);
            this.tabPage4.Controls.Add(this.externalDocumentUrlTextBox);
            this.tabPage4.Controls.Add(this.addReferenceButton);
            this.tabPage4.Controls.Add(this.includedXmltextBox);
            this.tabPage4.Controls.Add(this.objectIdPrefixTextBox);
            this.tabPage4.Controls.Add(this.label29);
            this.tabPage4.Location = new System.Drawing.Point(4, 22);
            this.tabPage4.Name = "tabPage4";
            this.tabPage4.Size = new System.Drawing.Size(688, 502);
            this.tabPage4.TabIndex = 1;
            this.tabPage4.Text = "Select document";
            // 
            // newSignatureCheckBox
            // 
            this.newSignatureCheckBox.Checked = true;
            this.newSignatureCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.newSignatureCheckBox.Location = new System.Drawing.Point(8, 373);
            this.newSignatureCheckBox.Name = "newSignatureCheckBox";
            this.newSignatureCheckBox.Size = new System.Drawing.Size(128, 24);
            this.newSignatureCheckBox.TabIndex = 10;
            this.newSignatureCheckBox.Text = "Start new signature";
            // 
            // nextObjectIdSuffixLabel
            // 
            this.nextObjectIdSuffixLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.nextObjectIdSuffixLabel.Location = new System.Drawing.Point(488, 416);
            this.nextObjectIdSuffixLabel.Name = "nextObjectIdSuffixLabel";
            this.nextObjectIdSuffixLabel.Size = new System.Drawing.Size(100, 23);
            this.nextObjectIdSuffixLabel.TabIndex = 9;
            // 
            // label31
            // 
            this.label31.Location = new System.Drawing.Point(368, 415);
            this.label31.Name = "label31";
            this.label31.Size = new System.Drawing.Size(112, 23);
            this.label31.TabIndex = 8;
            this.label31.Text = "Next object Id suffix:";
            // 
            // envelopedSignatureDocumentLocateButton
            // 
            this.envelopedSignatureDocumentLocateButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.envelopedSignatureDocumentLocateButton.Enabled = false;
            this.envelopedSignatureDocumentLocateButton.Location = new System.Drawing.Point(656, 280);
            this.envelopedSignatureDocumentLocateButton.Name = "envelopedSignatureDocumentLocateButton";
            this.envelopedSignatureDocumentLocateButton.Size = new System.Drawing.Size(24, 23);
            this.envelopedSignatureDocumentLocateButton.TabIndex = 7;
            this.envelopedSignatureDocumentLocateButton.Text = "...";
            this.envelopedSignatureDocumentLocateButton.Click += new System.EventHandler(this.envelopedSignatureDocumentLocateButton_Click);
            // 
            // envelopingDocumentTextBox
            // 
            this.envelopingDocumentTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.envelopingDocumentTextBox.Enabled = false;
            this.envelopingDocumentTextBox.Location = new System.Drawing.Point(136, 283);
            this.envelopingDocumentTextBox.Name = "envelopingDocumentTextBox";
            this.envelopingDocumentTextBox.Size = new System.Drawing.Size(512, 20);
            this.envelopingDocumentTextBox.TabIndex = 6;
            this.envelopingDocumentTextBox.Text = "EnvelopingDocument.xml";
            // 
            // envelopedSignatureRadioButton
            // 
            this.envelopedSignatureRadioButton.Location = new System.Drawing.Point(8, 283);
            this.envelopedSignatureRadioButton.Name = "envelopedSignatureRadioButton";
            this.envelopedSignatureRadioButton.Size = new System.Drawing.Size(128, 24);
            this.envelopedSignatureRadioButton.TabIndex = 5;
            this.envelopedSignatureRadioButton.Text = "Enveloped signature";
            this.envelopedSignatureRadioButton.CheckedChanged += new System.EventHandler(this.envelopedSignatureRadioButton_CheckedChanged);
            // 
            // externalDocumentRadioButton
            // 
            this.externalDocumentRadioButton.Location = new System.Drawing.Point(8, 24);
            this.externalDocumentRadioButton.Name = "externalDocumentRadioButton";
            this.externalDocumentRadioButton.Size = new System.Drawing.Size(128, 24);
            this.externalDocumentRadioButton.TabIndex = 0;
            this.externalDocumentRadioButton.Text = "Detached signature";
            this.externalDocumentRadioButton.CheckedChanged += new System.EventHandler(this.externalDocumentRadioButton_CheckedChanged);
            // 
            // includedXmlRadioButton
            // 
            this.includedXmlRadioButton.Checked = true;
            this.includedXmlRadioButton.Location = new System.Drawing.Point(8, 56);
            this.includedXmlRadioButton.Name = "includedXmlRadioButton";
            this.includedXmlRadioButton.Size = new System.Drawing.Size(128, 24);
            this.includedXmlRadioButton.TabIndex = 1;
            this.includedXmlRadioButton.TabStop = true;
            this.includedXmlRadioButton.Text = "Enveloping signature";
            this.includedXmlRadioButton.CheckedChanged += new System.EventHandler(this.includedXmlRadioButton_CheckedChanged);
            // 
            // externalDocumentUrlTextBox
            // 
            this.externalDocumentUrlTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.externalDocumentUrlTextBox.Enabled = false;
            this.externalDocumentUrlTextBox.Location = new System.Drawing.Point(136, 24);
            this.externalDocumentUrlTextBox.Name = "externalDocumentUrlTextBox";
            this.externalDocumentUrlTextBox.Size = new System.Drawing.Size(544, 20);
            this.externalDocumentUrlTextBox.TabIndex = 3;
            this.externalDocumentUrlTextBox.Text = "http://www.sitename.fr/Contracts/SaleContract14252235.doc";
            // 
            // addReferenceButton
            // 
            this.addReferenceButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.addReferenceButton.Location = new System.Drawing.Point(136, 368);
            this.addReferenceButton.Name = "addReferenceButton";
            this.addReferenceButton.Size = new System.Drawing.Size(136, 32);
            this.addReferenceButton.TabIndex = 4;
            this.addReferenceButton.Text = "Add Reference";
            this.addReferenceButton.Click += new System.EventHandler(this.addReferenceButton_Click);
            // 
            // includedXmltextBox
            // 
            this.includedXmltextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.includedXmltextBox.Location = new System.Drawing.Point(136, 56);
            this.includedXmltextBox.Multiline = true;
            this.includedXmltextBox.Name = "includedXmltextBox";
            this.includedXmltextBox.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.includedXmltextBox.Size = new System.Drawing.Size(544, 209);
            this.includedXmltextBox.TabIndex = 2;
            this.includedXmltextBox.Text = "<SalesContract><Invoice Number=\"341343\">1000€</Invoice></SalesContract>";
            // 
            // objectIdPrefixTextBox
            // 
            this.objectIdPrefixTextBox.Location = new System.Drawing.Point(136, 415);
            this.objectIdPrefixTextBox.Name = "objectIdPrefixTextBox";
            this.objectIdPrefixTextBox.Size = new System.Drawing.Size(192, 20);
            this.objectIdPrefixTextBox.TabIndex = 3;
            this.objectIdPrefixTextBox.Text = "ObjectId-";
            // 
            // label29
            // 
            this.label29.Location = new System.Drawing.Point(8, 415);
            this.label29.Name = "label29";
            this.label29.Size = new System.Drawing.Size(120, 23);
            this.label29.TabIndex = 2;
            this.label29.Text = "Object Id prefix:";
            // 
            // tabPage3
            // 
            this.tabPage3.Controls.Add(this.groupBox15);
            this.tabPage3.Controls.Add(this.groupBox14);
            this.tabPage3.Location = new System.Drawing.Point(4, 22);
            this.tabPage3.Name = "tabPage3";
            this.tabPage3.Size = new System.Drawing.Size(688, 502);
            this.tabPage3.TabIndex = 0;
            this.tabPage3.Text = "Select certificate";
            // 
            // groupBox15
            // 
            this.groupBox15.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox15.Controls.Add(this.includeKeyValueCheckBox);
            this.groupBox15.Controls.Add(this.selectCertificateButton);
            this.groupBox15.Location = new System.Drawing.Point(8, 8);
            this.groupBox15.Name = "groupBox15";
            this.groupBox15.Size = new System.Drawing.Size(672, 98);
            this.groupBox15.TabIndex = 6;
            this.groupBox15.TabStop = false;
            this.groupBox15.Text = "Select a certificate";
            // 
            // includeKeyValueCheckBox
            // 
            this.includeKeyValueCheckBox.Checked = true;
            this.includeKeyValueCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.includeKeyValueCheckBox.Location = new System.Drawing.Point(16, 24);
            this.includeKeyValueCheckBox.Name = "includeKeyValueCheckBox";
            this.includeKeyValueCheckBox.Size = new System.Drawing.Size(176, 24);
            this.includeKeyValueCheckBox.TabIndex = 1;
            this.includeKeyValueCheckBox.Text = "Include Key Value";
            // 
            // selectCertificateButton
            // 
            this.selectCertificateButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.selectCertificateButton.Location = new System.Drawing.Point(11, 54);
            this.selectCertificateButton.Name = "selectCertificateButton";
            this.selectCertificateButton.Size = new System.Drawing.Size(108, 36);
            this.selectCertificateButton.TabIndex = 0;
            this.selectCertificateButton.Text = "Select certificate...";
            this.selectCertificateButton.Click += new System.EventHandler(this.selectCertificateButton_Click);
            // 
            // groupBox14
            // 
            this.groupBox14.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox14.Controls.Add(this.viewCertificateButton);
            this.groupBox14.Controls.Add(this.label4);
            this.groupBox14.Controls.Add(this.certificateInfoIssuedLabel);
            this.groupBox14.Controls.Add(this.label5);
            this.groupBox14.Controls.Add(this.certificateInfoIssuerLabel);
            this.groupBox14.Location = new System.Drawing.Point(8, 112);
            this.groupBox14.Name = "groupBox14";
            this.groupBox14.Size = new System.Drawing.Size(672, 384);
            this.groupBox14.TabIndex = 5;
            this.groupBox14.TabStop = false;
            this.groupBox14.Text = "Certificate information";
            // 
            // viewCertificateButton
            // 
            this.viewCertificateButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.viewCertificateButton.Enabled = false;
            this.viewCertificateButton.Location = new System.Drawing.Point(11, 166);
            this.viewCertificateButton.Name = "viewCertificateButton";
            this.viewCertificateButton.Size = new System.Drawing.Size(108, 36);
            this.viewCertificateButton.TabIndex = 5;
            this.viewCertificateButton.Text = "View certificate...";
            this.viewCertificateButton.Click += new System.EventHandler(this.viewCertificateButton_Click);
            // 
            // label4
            // 
            this.label4.Location = new System.Drawing.Point(9, 24);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(112, 23);
            this.label4.TabIndex = 1;
            this.label4.Text = "Certificate issued to:";
            // 
            // certificateInfoIssuedLabel
            // 
            this.certificateInfoIssuedLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.certificateInfoIssuedLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.certificateInfoIssuedLabel.Location = new System.Drawing.Point(129, 24);
            this.certificateInfoIssuedLabel.Name = "certificateInfoIssuedLabel";
            this.certificateInfoIssuedLabel.Size = new System.Drawing.Size(536, 80);
            this.certificateInfoIssuedLabel.TabIndex = 2;
            // 
            // label5
            // 
            this.label5.Location = new System.Drawing.Point(9, 104);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(100, 23);
            this.label5.TabIndex = 3;
            this.label5.Text = "CA:";
            // 
            // certificateInfoIssuerLabel
            // 
            this.certificateInfoIssuerLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.certificateInfoIssuerLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.certificateInfoIssuerLabel.Location = new System.Drawing.Point(129, 104);
            this.certificateInfoIssuerLabel.Name = "certificateInfoIssuerLabel";
            this.certificateInfoIssuerLabel.Size = new System.Drawing.Size(536, 56);
            this.certificateInfoIssuerLabel.TabIndex = 4;
            // 
            // tabPage5
            // 
            this.tabPage5.Controls.Add(this.groupBox13);
            this.tabPage5.Controls.Add(this.groupBox7);
            this.tabPage5.Controls.Add(this.groupBox5);
            this.tabPage5.Controls.Add(this.groupBox2);
            this.tabPage5.Location = new System.Drawing.Point(4, 22);
            this.tabPage5.Name = "tabPage5";
            this.tabPage5.Size = new System.Drawing.Size(688, 502);
            this.tabPage5.TabIndex = 2;
            this.tabPage5.Text = "XAdES";
            // 
            // groupBox13
            // 
            this.groupBox13.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox13.Controls.Add(this.signatureValueIdTextBox);
            this.groupBox13.Controls.Add(this.label2);
            this.groupBox13.Controls.Add(this.signatureIdTextBox);
            this.groupBox13.Controls.Add(this.label28);
            this.groupBox13.Controls.Add(this.signingTimeTextBox);
            this.groupBox13.Controls.Add(this.label3);
            this.groupBox13.Location = new System.Drawing.Point(8, 8);
            this.groupBox13.Name = "groupBox13";
            this.groupBox13.Size = new System.Drawing.Size(672, 96);
            this.groupBox13.TabIndex = 15;
            this.groupBox13.TabStop = false;
            this.groupBox13.Text = "Signature Id and Signing time";
            // 
            // signatureValueIdTextBox
            // 
            this.signatureValueIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureValueIdTextBox.Location = new System.Drawing.Point(160, 64);
            this.signatureValueIdTextBox.Name = "signatureValueIdTextBox";
            this.signatureValueIdTextBox.Size = new System.Drawing.Size(504, 20);
            this.signatureValueIdTextBox.TabIndex = 3;
            this.signatureValueIdTextBox.Text = "SignatureValueId";
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(8, 64);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(100, 23);
            this.label2.TabIndex = 2;
            this.label2.Text = "Signature Value Id:";
            // 
            // signatureIdTextBox
            // 
            this.signatureIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureIdTextBox.Location = new System.Drawing.Point(160, 16);
            this.signatureIdTextBox.Name = "signatureIdTextBox";
            this.signatureIdTextBox.Size = new System.Drawing.Size(504, 20);
            this.signatureIdTextBox.TabIndex = 1;
            this.signatureIdTextBox.Text = "SignatureId";
            // 
            // label28
            // 
            this.label28.Location = new System.Drawing.Point(8, 16);
            this.label28.Name = "label28";
            this.label28.Size = new System.Drawing.Size(100, 23);
            this.label28.TabIndex = 0;
            this.label28.Text = "Signature Id:";
            // 
            // signingTimeTextBox
            // 
            this.signingTimeTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signingTimeTextBox.Location = new System.Drawing.Point(160, 40);
            this.signingTimeTextBox.Name = "signingTimeTextBox";
            this.signingTimeTextBox.Size = new System.Drawing.Size(504, 20);
            this.signingTimeTextBox.TabIndex = 1;
            // 
            // label3
            // 
            this.label3.Location = new System.Drawing.Point(8, 40);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(88, 23);
            this.label3.TabIndex = 0;
            this.label3.Text = "Signing time:";
            // 
            // groupBox7
            // 
            this.groupBox7.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox7.Controls.Add(this.label17);
            this.groupBox7.Controls.Add(this.label16);
            this.groupBox7.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.groupBox7.Location = new System.Drawing.Point(8, 272);
            this.groupBox7.Name = "groupBox7";
            this.groupBox7.Size = new System.Drawing.Size(672, 64);
            this.groupBox7.TabIndex = 14;
            this.groupBox7.TabStop = false;
            this.groupBox7.Text = "Signature Policy Identifier";
            // 
            // label17
            // 
            this.label17.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label17.Location = new System.Drawing.Point(160, 24);
            this.label17.Name = "label17";
            this.label17.Size = new System.Drawing.Size(100, 23);
            this.label17.TabIndex = 1;
            this.label17.Text = "True";
            // 
            // label16
            // 
            this.label16.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label16.Location = new System.Drawing.Point(8, 24);
            this.label16.Name = "label16";
            this.label16.Size = new System.Drawing.Size(136, 23);
            this.label16.TabIndex = 0;
            this.label16.Text = "Signature Policy Implied:";
            // 
            // groupBox5
            // 
            this.groupBox5.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox5.Controls.Add(this.issuerNameLabel);
            this.groupBox5.Controls.Add(this.label13);
            this.groupBox5.Controls.Add(this.digestValueLabel);
            this.groupBox5.Controls.Add(this.digestMethodLabel);
            this.groupBox5.Controls.Add(this.issuerSerialLabel);
            this.groupBox5.Controls.Add(this.label12);
            this.groupBox5.Controls.Add(this.label11);
            this.groupBox5.Controls.Add(this.label10);
            this.groupBox5.Location = new System.Drawing.Point(8, 112);
            this.groupBox5.Name = "groupBox5";
            this.groupBox5.Size = new System.Drawing.Size(672, 152);
            this.groupBox5.TabIndex = 13;
            this.groupBox5.TabStop = false;
            this.groupBox5.Text = "Signing Certificate";
            // 
            // issuerNameLabel
            // 
            this.issuerNameLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.issuerNameLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.issuerNameLabel.Location = new System.Drawing.Point(160, 48);
            this.issuerNameLabel.Name = "issuerNameLabel";
            this.issuerNameLabel.Size = new System.Drawing.Size(504, 48);
            this.issuerNameLabel.TabIndex = 7;
            // 
            // label13
            // 
            this.label13.Location = new System.Drawing.Point(8, 48);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(100, 23);
            this.label13.TabIndex = 6;
            this.label13.Text = "Issuer Name:";
            // 
            // digestValueLabel
            // 
            this.digestValueLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.digestValueLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.digestValueLabel.Location = new System.Drawing.Point(160, 120);
            this.digestValueLabel.Name = "digestValueLabel";
            this.digestValueLabel.Size = new System.Drawing.Size(504, 23);
            this.digestValueLabel.TabIndex = 5;
            // 
            // digestMethodLabel
            // 
            this.digestMethodLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.digestMethodLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.digestMethodLabel.Location = new System.Drawing.Point(160, 96);
            this.digestMethodLabel.Name = "digestMethodLabel";
            this.digestMethodLabel.Size = new System.Drawing.Size(504, 23);
            this.digestMethodLabel.TabIndex = 4;
            // 
            // issuerSerialLabel
            // 
            this.issuerSerialLabel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.issuerSerialLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.issuerSerialLabel.Location = new System.Drawing.Point(160, 24);
            this.issuerSerialLabel.Name = "issuerSerialLabel";
            this.issuerSerialLabel.Size = new System.Drawing.Size(504, 23);
            this.issuerSerialLabel.TabIndex = 3;
            // 
            // label12
            // 
            this.label12.Location = new System.Drawing.Point(8, 120);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(100, 23);
            this.label12.TabIndex = 2;
            this.label12.Text = "Digest Value:";
            // 
            // label11
            // 
            this.label11.Location = new System.Drawing.Point(8, 96);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(100, 23);
            this.label11.TabIndex = 1;
            this.label11.Text = "Digest Method:";
            // 
            // label10
            // 
            this.label10.Location = new System.Drawing.Point(8, 24);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(100, 23);
            this.label10.TabIndex = 0;
            this.label10.Text = "Issuer Serial:";
            // 
            // groupBox2
            // 
            this.groupBox2.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox2.Controls.Add(this.includeSignatureProductionPlaceCheckBox);
            this.groupBox2.Controls.Add(this.signatureCountryNameTextBox);
            this.groupBox2.Controls.Add(this.label9);
            this.groupBox2.Controls.Add(this.signaturePostalCodeTextBox);
            this.groupBox2.Controls.Add(this.label8);
            this.groupBox2.Controls.Add(this.signatureStateOrProvinceTextBox);
            this.groupBox2.Controls.Add(this.label7);
            this.groupBox2.Controls.Add(this.signatureCityTextBox);
            this.groupBox2.Controls.Add(this.label6);
            this.groupBox2.Location = new System.Drawing.Point(8, 344);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(672, 152);
            this.groupBox2.TabIndex = 11;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Signature Production Place";
            // 
            // includeSignatureProductionPlaceCheckBox
            // 
            this.includeSignatureProductionPlaceCheckBox.Location = new System.Drawing.Point(11, 21);
            this.includeSignatureProductionPlaceCheckBox.Name = "includeSignatureProductionPlaceCheckBox";
            this.includeSignatureProductionPlaceCheckBox.Size = new System.Drawing.Size(104, 24);
            this.includeSignatureProductionPlaceCheckBox.TabIndex = 11;
            this.includeSignatureProductionPlaceCheckBox.Text = "Include";
            this.includeSignatureProductionPlaceCheckBox.CheckedChanged += new System.EventHandler(this.includeSignatureProductionPlaceCheckBox_CheckedChanged);
            // 
            // signatureCountryNameTextBox
            // 
            this.signatureCountryNameTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureCountryNameTextBox.Enabled = false;
            this.signatureCountryNameTextBox.Location = new System.Drawing.Point(160, 120);
            this.signatureCountryNameTextBox.Name = "signatureCountryNameTextBox";
            this.signatureCountryNameTextBox.Size = new System.Drawing.Size(504, 20);
            this.signatureCountryNameTextBox.TabIndex = 10;
            this.signatureCountryNameTextBox.Text = "France";
            // 
            // label9
            // 
            this.label9.Location = new System.Drawing.Point(8, 120);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(100, 23);
            this.label9.TabIndex = 9;
            this.label9.Text = "Country";
            // 
            // signaturePostalCodeTextBox
            // 
            this.signaturePostalCodeTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signaturePostalCodeTextBox.Enabled = false;
            this.signaturePostalCodeTextBox.Location = new System.Drawing.Point(160, 96);
            this.signaturePostalCodeTextBox.Name = "signaturePostalCodeTextBox";
            this.signaturePostalCodeTextBox.Size = new System.Drawing.Size(504, 20);
            this.signaturePostalCodeTextBox.TabIndex = 8;
            this.signaturePostalCodeTextBox.Text = "92130";
            // 
            // label8
            // 
            this.label8.Location = new System.Drawing.Point(8, 96);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(144, 23);
            this.label8.TabIndex = 7;
            this.label8.Text = "Postal code:";
            // 
            // signatureStateOrProvinceTextBox
            // 
            this.signatureStateOrProvinceTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureStateOrProvinceTextBox.Enabled = false;
            this.signatureStateOrProvinceTextBox.Location = new System.Drawing.Point(160, 72);
            this.signatureStateOrProvinceTextBox.Name = "signatureStateOrProvinceTextBox";
            this.signatureStateOrProvinceTextBox.Size = new System.Drawing.Size(504, 20);
            this.signatureStateOrProvinceTextBox.TabIndex = 6;
            this.signatureStateOrProvinceTextBox.Text = " ";
            // 
            // label7
            // 
            this.label7.Location = new System.Drawing.Point(8, 72);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(144, 23);
            this.label7.TabIndex = 5;
            this.label7.Text = "Signature state or province:";
            // 
            // signatureCityTextBox
            // 
            this.signatureCityTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureCityTextBox.Enabled = false;
            this.signatureCityTextBox.Location = new System.Drawing.Point(160, 48);
            this.signatureCityTextBox.Name = "signatureCityTextBox";
            this.signatureCityTextBox.Size = new System.Drawing.Size(504, 20);
            this.signatureCityTextBox.TabIndex = 4;
            this.signatureCityTextBox.Text = "Issy les Moulineaux";
            // 
            // label6
            // 
            this.label6.Location = new System.Drawing.Point(8, 48);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(100, 23);
            this.label6.TabIndex = 3;
            this.label6.Text = "Signature city:";
            // 
            // tabPage6
            // 
            this.tabPage6.Controls.Add(this.groupBox10);
            this.tabPage6.Controls.Add(this.groupBox9);
            this.tabPage6.Controls.Add(this.groupBox11);
            this.tabPage6.Controls.Add(this.addXadesInfoButton);
            this.tabPage6.Location = new System.Drawing.Point(4, 22);
            this.tabPage6.Name = "tabPage6";
            this.tabPage6.Size = new System.Drawing.Size(688, 502);
            this.tabPage6.TabIndex = 5;
            this.tabPage6.Text = "XAdES (2)";
            // 
            // groupBox10
            // 
            this.groupBox10.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox10.Controls.Add(this.commitmentTypeIndicatorQualifierComboBox);
            this.groupBox10.Controls.Add(this.label23);
            this.groupBox10.Controls.Add(this.commitmentTypeIdentifierURITextBox);
            this.groupBox10.Controls.Add(this.label22);
            this.groupBox10.Controls.Add(this.label21);
            this.groupBox10.Controls.Add(this.label20);
            this.groupBox10.Controls.Add(this.commitmentTypeIndicationIdTextBox);
            this.groupBox10.Controls.Add(this.label19);
            this.groupBox10.Controls.Add(this.includeCommitmentTypeIndicationCheckBox);
            this.groupBox10.Location = new System.Drawing.Point(8, 256);
            this.groupBox10.Name = "groupBox10";
            this.groupBox10.Size = new System.Drawing.Size(672, 160);
            this.groupBox10.TabIndex = 13;
            this.groupBox10.TabStop = false;
            this.groupBox10.Text = "Commitment Type Indication";
            // 
            // commitmentTypeIndicatorQualifierComboBox
            // 
            this.commitmentTypeIndicatorQualifierComboBox.Enabled = false;
            this.commitmentTypeIndicatorQualifierComboBox.Items.AddRange(new object[] {
            "",
            "OIDAsURN",
            "OIDAsURI"});
            this.commitmentTypeIndicatorQualifierComboBox.Location = new System.Drawing.Point(160, 48);
            this.commitmentTypeIndicatorQualifierComboBox.Name = "commitmentTypeIndicatorQualifierComboBox";
            this.commitmentTypeIndicatorQualifierComboBox.Size = new System.Drawing.Size(121, 21);
            this.commitmentTypeIndicatorQualifierComboBox.TabIndex = 21;
            // 
            // label23
            // 
            this.label23.Location = new System.Drawing.Point(8, 48);
            this.label23.Name = "label23";
            this.label23.Size = new System.Drawing.Size(100, 23);
            this.label23.TabIndex = 20;
            this.label23.Text = "Qualifier:";
            // 
            // commitmentTypeIdentifierURITextBox
            // 
            this.commitmentTypeIdentifierURITextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.commitmentTypeIdentifierURITextBox.Enabled = false;
            this.commitmentTypeIdentifierURITextBox.Location = new System.Drawing.Point(160, 72);
            this.commitmentTypeIdentifierURITextBox.Name = "commitmentTypeIdentifierURITextBox";
            this.commitmentTypeIdentifierURITextBox.Size = new System.Drawing.Size(504, 20);
            this.commitmentTypeIdentifierURITextBox.TabIndex = 19;
            this.commitmentTypeIdentifierURITextBox.Text = "urn:oid:1.2.840.113556.1.8000.652.1";
            // 
            // label22
            // 
            this.label22.Location = new System.Drawing.Point(8, 72);
            this.label22.Name = "label22";
            this.label22.Size = new System.Drawing.Size(100, 23);
            this.label22.TabIndex = 18;
            this.label22.Text = "Identifier URI:";
            // 
            // label21
            // 
            this.label21.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label21.Location = new System.Drawing.Point(160, 120);
            this.label21.Name = "label21";
            this.label21.Size = new System.Drawing.Size(100, 23);
            this.label21.TabIndex = 17;
            this.label21.Text = "True";
            // 
            // label20
            // 
            this.label20.Location = new System.Drawing.Point(8, 120);
            this.label20.Name = "label20";
            this.label20.Size = new System.Drawing.Size(144, 23);
            this.label20.TabIndex = 16;
            this.label20.Text = "All Signed Data Objects:";
            // 
            // commitmentTypeIndicationIdTextBox
            // 
            this.commitmentTypeIndicationIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.commitmentTypeIndicationIdTextBox.Enabled = false;
            this.commitmentTypeIndicationIdTextBox.Location = new System.Drawing.Point(160, 96);
            this.commitmentTypeIndicationIdTextBox.Name = "commitmentTypeIndicationIdTextBox";
            this.commitmentTypeIndicationIdTextBox.Size = new System.Drawing.Size(504, 20);
            this.commitmentTypeIndicationIdTextBox.TabIndex = 15;
            // 
            // label19
            // 
            this.label19.Location = new System.Drawing.Point(8, 96);
            this.label19.Name = "label19";
            this.label19.Size = new System.Drawing.Size(144, 23);
            this.label19.TabIndex = 14;
            this.label19.Text = "Commitment Description:";
            // 
            // includeCommitmentTypeIndicationCheckBox
            // 
            this.includeCommitmentTypeIndicationCheckBox.Location = new System.Drawing.Point(8, 16);
            this.includeCommitmentTypeIndicationCheckBox.Name = "includeCommitmentTypeIndicationCheckBox";
            this.includeCommitmentTypeIndicationCheckBox.Size = new System.Drawing.Size(104, 24);
            this.includeCommitmentTypeIndicationCheckBox.TabIndex = 13;
            this.includeCommitmentTypeIndicationCheckBox.Text = "Include";
            this.includeCommitmentTypeIndicationCheckBox.CheckedChanged += new System.EventHandler(this.includeCommitmentTypeIndicationCheckBox_CheckedChanged);
            // 
            // groupBox9
            // 
            this.groupBox9.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox9.Controls.Add(this.label18);
            this.groupBox9.Controls.Add(this.claimedRoleTextBox);
            this.groupBox9.Controls.Add(this.includeSignerRoleCheckBox);
            this.groupBox9.Location = new System.Drawing.Point(8, 144);
            this.groupBox9.Name = "groupBox9";
            this.groupBox9.Size = new System.Drawing.Size(672, 104);
            this.groupBox9.TabIndex = 12;
            this.groupBox9.TabStop = false;
            this.groupBox9.Text = "Signer Role";
            // 
            // label18
            // 
            this.label18.Location = new System.Drawing.Point(8, 48);
            this.label18.Name = "label18";
            this.label18.Size = new System.Drawing.Size(100, 23);
            this.label18.TabIndex = 14;
            this.label18.Text = "Claimed Role:";
            // 
            // claimedRoleTextBox
            // 
            this.claimedRoleTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.claimedRoleTextBox.Enabled = false;
            this.claimedRoleTextBox.Location = new System.Drawing.Point(160, 48);
            this.claimedRoleTextBox.Multiline = true;
            this.claimedRoleTextBox.Name = "claimedRoleTextBox";
            this.claimedRoleTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.claimedRoleTextBox.Size = new System.Drawing.Size(504, 48);
            this.claimedRoleTextBox.TabIndex = 13;
            this.claimedRoleTextBox.Text = "<SalesDirector>Acting as sales director</SalesDirector>";
            // 
            // includeSignerRoleCheckBox
            // 
            this.includeSignerRoleCheckBox.Location = new System.Drawing.Point(8, 16);
            this.includeSignerRoleCheckBox.Name = "includeSignerRoleCheckBox";
            this.includeSignerRoleCheckBox.Size = new System.Drawing.Size(104, 24);
            this.includeSignerRoleCheckBox.TabIndex = 12;
            this.includeSignerRoleCheckBox.Text = "Include";
            this.includeSignerRoleCheckBox.CheckedChanged += new System.EventHandler(this.includeSignerRoleCheckBox_CheckedChanged);
            // 
            // groupBox11
            // 
            this.groupBox11.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox11.Controls.Add(this.dataObjectReferenceTextBox);
            this.groupBox11.Controls.Add(this.dataObjectFormatMimetypeTextBox);
            this.groupBox11.Controls.Add(this.dataObjectDescriptionTextBox);
            this.groupBox11.Controls.Add(this.label26);
            this.groupBox11.Controls.Add(this.label25);
            this.groupBox11.Controls.Add(this.label24);
            this.groupBox11.Controls.Add(this.includeDataObjectFormatCheckBox);
            this.groupBox11.Location = new System.Drawing.Point(8, 8);
            this.groupBox11.Name = "groupBox11";
            this.groupBox11.Size = new System.Drawing.Size(672, 128);
            this.groupBox11.TabIndex = 0;
            this.groupBox11.TabStop = false;
            this.groupBox11.Text = "Data Object Format";
            // 
            // dataObjectReferenceTextBox
            // 
            this.dataObjectReferenceTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.dataObjectReferenceTextBox.Enabled = false;
            this.dataObjectReferenceTextBox.Location = new System.Drawing.Point(152, 96);
            this.dataObjectReferenceTextBox.Name = "dataObjectReferenceTextBox";
            this.dataObjectReferenceTextBox.Size = new System.Drawing.Size(512, 20);
            this.dataObjectReferenceTextBox.TabIndex = 18;
            this.dataObjectReferenceTextBox.Text = "#object-1";
            // 
            // dataObjectFormatMimetypeTextBox
            // 
            this.dataObjectFormatMimetypeTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.dataObjectFormatMimetypeTextBox.Enabled = false;
            this.dataObjectFormatMimetypeTextBox.Location = new System.Drawing.Point(152, 72);
            this.dataObjectFormatMimetypeTextBox.Name = "dataObjectFormatMimetypeTextBox";
            this.dataObjectFormatMimetypeTextBox.Size = new System.Drawing.Size(512, 20);
            this.dataObjectFormatMimetypeTextBox.TabIndex = 17;
            this.dataObjectFormatMimetypeTextBox.Text = "text/plain";
            // 
            // dataObjectDescriptionTextBox
            // 
            this.dataObjectDescriptionTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.dataObjectDescriptionTextBox.Enabled = false;
            this.dataObjectDescriptionTextBox.Location = new System.Drawing.Point(152, 48);
            this.dataObjectDescriptionTextBox.Name = "dataObjectDescriptionTextBox";
            this.dataObjectDescriptionTextBox.Size = new System.Drawing.Size(512, 20);
            this.dataObjectDescriptionTextBox.TabIndex = 16;
            // 
            // label26
            // 
            this.label26.Location = new System.Drawing.Point(8, 96);
            this.label26.Name = "label26";
            this.label26.Size = new System.Drawing.Size(100, 23);
            this.label26.TabIndex = 15;
            this.label26.Text = "Object Reference:";
            // 
            // label25
            // 
            this.label25.Location = new System.Drawing.Point(8, 72);
            this.label25.Name = "label25";
            this.label25.Size = new System.Drawing.Size(100, 23);
            this.label25.TabIndex = 14;
            this.label25.Text = "Mimetype:";
            // 
            // label24
            // 
            this.label24.Location = new System.Drawing.Point(8, 48);
            this.label24.Name = "label24";
            this.label24.Size = new System.Drawing.Size(100, 23);
            this.label24.TabIndex = 13;
            this.label24.Text = "Description:";
            // 
            // includeDataObjectFormatCheckBox
            // 
            this.includeDataObjectFormatCheckBox.Location = new System.Drawing.Point(8, 16);
            this.includeDataObjectFormatCheckBox.Name = "includeDataObjectFormatCheckBox";
            this.includeDataObjectFormatCheckBox.Size = new System.Drawing.Size(104, 24);
            this.includeDataObjectFormatCheckBox.TabIndex = 12;
            this.includeDataObjectFormatCheckBox.Text = "Include";
            this.includeDataObjectFormatCheckBox.CheckedChanged += new System.EventHandler(this.includeDataObjectFormatCheckBox_CheckedChanged);
            // 
            // addXadesInfoButton
            // 
            this.addXadesInfoButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.addXadesInfoButton.Location = new System.Drawing.Point(249, 437);
            this.addXadesInfoButton.Name = "addXadesInfoButton";
            this.addXadesInfoButton.Size = new System.Drawing.Size(195, 35);
            this.addXadesInfoButton.TabIndex = 2;
            this.addXadesInfoButton.Text = "Add XAdES information";
            this.addXadesInfoButton.Click += new System.EventHandler(this.addXadesInfoButton_Click);
            // 
            // tabPage7
            // 
            this.tabPage7.Controls.Add(this.computeSignatureButton);
            this.tabPage7.Location = new System.Drawing.Point(4, 22);
            this.tabPage7.Name = "tabPage7";
            this.tabPage7.Size = new System.Drawing.Size(688, 502);
            this.tabPage7.TabIndex = 4;
            this.tabPage7.Text = "Sign";
            // 
            // computeSignatureButton
            // 
            this.computeSignatureButton.Location = new System.Drawing.Point(259, 17);
            this.computeSignatureButton.Name = "computeSignatureButton";
            this.computeSignatureButton.Size = new System.Drawing.Size(159, 38);
            this.computeSignatureButton.TabIndex = 5;
            this.computeSignatureButton.Text = "Compute signature...";
            this.computeSignatureButton.Click += new System.EventHandler(this.computeSignatureButton_Click);
            // 
            // tabPage8
            // 
            this.tabPage8.Controls.Add(this.addCounterSignatureButton);
            this.tabPage8.Location = new System.Drawing.Point(4, 22);
            this.tabPage8.Name = "tabPage8";
            this.tabPage8.Size = new System.Drawing.Size(688, 502);
            this.tabPage8.TabIndex = 6;
            this.tabPage8.Text = "Counter signature";
            // 
            // addCounterSignatureButton
            // 
            this.addCounterSignatureButton.Location = new System.Drawing.Point(264, 21);
            this.addCounterSignatureButton.Name = "addCounterSignatureButton";
            this.addCounterSignatureButton.Size = new System.Drawing.Size(146, 38);
            this.addCounterSignatureButton.TabIndex = 1;
            this.addCounterSignatureButton.Text = "Add counter signature...";
            this.addCounterSignatureButton.Click += new System.EventHandler(this.addCounterSignatureButton_Click);
            // 
            // tabPage10
            // 
            this.tabPage10.Controls.Add(this.groupBox8);
            this.tabPage10.Location = new System.Drawing.Point(4, 22);
            this.tabPage10.Name = "tabPage10";
            this.tabPage10.Size = new System.Drawing.Size(688, 502);
            this.tabPage10.TabIndex = 8;
            this.tabPage10.Text = "XAdES-T";
            // 
            // groupBox8
            // 
            this.groupBox8.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox8.Controls.Add(this.label27);
            this.groupBox8.Controls.Add(this.signatureTimeStampIdTextBox);
            this.groupBox8.Controls.Add(this.requestTimeStampButton);
            this.groupBox8.Controls.Add(this.tsaCertificateInResponseCheckBox);
            this.groupBox8.Controls.Add(this.tsaUriTextBox);
            this.groupBox8.Controls.Add(this.label30);
            this.groupBox8.Location = new System.Drawing.Point(8, 8);
            this.groupBox8.Name = "groupBox8";
            this.groupBox8.Size = new System.Drawing.Size(672, 167);
            this.groupBox8.TabIndex = 1;
            this.groupBox8.TabStop = false;
            this.groupBox8.Text = "Inject timestamp";
            // 
            // label27
            // 
            this.label27.Location = new System.Drawing.Point(8, 48);
            this.label27.Name = "label27";
            this.label27.Size = new System.Drawing.Size(144, 23);
            this.label27.TabIndex = 7;
            this.label27.Text = "Signature timestamp ID:";
            // 
            // signatureTimeStampIdTextBox
            // 
            this.signatureTimeStampIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.signatureTimeStampIdTextBox.Location = new System.Drawing.Point(152, 48);
            this.signatureTimeStampIdTextBox.Name = "signatureTimeStampIdTextBox";
            this.signatureTimeStampIdTextBox.Size = new System.Drawing.Size(512, 20);
            this.signatureTimeStampIdTextBox.TabIndex = 6;
            this.signatureTimeStampIdTextBox.Text = "SignatureTimeStampId";
            // 
            // requestTimeStampButton
            // 
            this.requestTimeStampButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.requestTimeStampButton.Location = new System.Drawing.Point(258, 112);
            this.requestTimeStampButton.Name = "requestTimeStampButton";
            this.requestTimeStampButton.Size = new System.Drawing.Size(172, 39);
            this.requestTimeStampButton.TabIndex = 5;
            this.requestTimeStampButton.Text = "Request and add TimeStamp";
            this.requestTimeStampButton.Click += new System.EventHandler(this.requestTimeStampButton_Click);
            // 
            // tsaCertificateInResponseCheckBox
            // 
            this.tsaCertificateInResponseCheckBox.Checked = true;
            this.tsaCertificateInResponseCheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.tsaCertificateInResponseCheckBox.Location = new System.Drawing.Point(11, 74);
            this.tsaCertificateInResponseCheckBox.Name = "tsaCertificateInResponseCheckBox";
            this.tsaCertificateInResponseCheckBox.Size = new System.Drawing.Size(168, 24);
            this.tsaCertificateInResponseCheckBox.TabIndex = 4;
            this.tsaCertificateInResponseCheckBox.Text = "TSA certificate in response";
            // 
            // tsaUriTextBox
            // 
            this.tsaUriTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.tsaUriTextBox.Location = new System.Drawing.Point(152, 24);
            this.tsaUriTextBox.Name = "tsaUriTextBox";
            this.tsaUriTextBox.Size = new System.Drawing.Size(512, 20);
            this.tsaUriTextBox.TabIndex = 2;
            // 
            // label30
            // 
            this.label30.Location = new System.Drawing.Point(8, 24);
            this.label30.Name = "label30";
            this.label30.Size = new System.Drawing.Size(144, 23);
            this.label30.TabIndex = 1;
            this.label30.Text = "Timestamp Authority URI:";
            // 
            // tabPage9
            // 
            this.tabPage9.Controls.Add(this.groupBox4);
            this.tabPage9.Location = new System.Drawing.Point(4, 22);
            this.tabPage9.Name = "tabPage9";
            this.tabPage9.Size = new System.Drawing.Size(688, 502);
            this.tabPage9.TabIndex = 7;
            this.tabPage9.Text = "XAdES-C";
            // 
            // groupBox4
            // 
            this.groupBox4.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox4.Controls.Add(this.completeRevocationRefsIdTextBox);
            this.groupBox4.Controls.Add(this.label34);
            this.groupBox4.Controls.Add(this.completeCertificateRefsTextBox);
            this.groupBox4.Controls.Add(this.label33);
            this.groupBox4.Controls.Add(this.crlFileLocateButton);
            this.groupBox4.Controls.Add(this.crlFileTextBox);
            this.groupBox4.Controls.Add(this.label32);
            this.groupBox4.Controls.Add(this.includeCrlCheckBox);
            this.groupBox4.Controls.Add(this.injectXadesCInformationButton);
            this.groupBox4.Controls.Add(this.includeCertificateChainCheckBox);
            this.groupBox4.Location = new System.Drawing.Point(8, 8);
            this.groupBox4.Name = "groupBox4";
            this.groupBox4.Size = new System.Drawing.Size(672, 248);
            this.groupBox4.TabIndex = 3;
            this.groupBox4.TabStop = false;
            this.groupBox4.Text = "Inject complete certificate chain and revocation information";
            // 
            // completeRevocationRefsIdTextBox
            // 
            this.completeRevocationRefsIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.completeRevocationRefsIdTextBox.Enabled = false;
            this.completeRevocationRefsIdTextBox.Location = new System.Drawing.Point(120, 151);
            this.completeRevocationRefsIdTextBox.Name = "completeRevocationRefsIdTextBox";
            this.completeRevocationRefsIdTextBox.Size = new System.Drawing.Size(544, 20);
            this.completeRevocationRefsIdTextBox.TabIndex = 9;
            this.completeRevocationRefsIdTextBox.Text = "CompleteRevocationRefsId";
            // 
            // label34
            // 
            this.label34.Location = new System.Drawing.Point(8, 151);
            this.label34.Name = "label34";
            this.label34.Size = new System.Drawing.Size(112, 23);
            this.label34.TabIndex = 8;
            this.label34.Text = "RevocationRefs ID:";
            // 
            // completeCertificateRefsTextBox
            // 
            this.completeCertificateRefsTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.completeCertificateRefsTextBox.Enabled = false;
            this.completeCertificateRefsTextBox.Location = new System.Drawing.Point(120, 50);
            this.completeCertificateRefsTextBox.Name = "completeCertificateRefsTextBox";
            this.completeCertificateRefsTextBox.Size = new System.Drawing.Size(544, 20);
            this.completeCertificateRefsTextBox.TabIndex = 7;
            this.completeCertificateRefsTextBox.Text = "CompleteCertificateRefsId";
            // 
            // label33
            // 
            this.label33.Location = new System.Drawing.Point(8, 50);
            this.label33.Name = "label33";
            this.label33.Size = new System.Drawing.Size(100, 23);
            this.label33.TabIndex = 6;
            this.label33.Text = "CertificateRefs ID:";
            // 
            // crlFileLocateButton
            // 
            this.crlFileLocateButton.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.crlFileLocateButton.Enabled = false;
            this.crlFileLocateButton.Location = new System.Drawing.Point(640, 120);
            this.crlFileLocateButton.Name = "crlFileLocateButton";
            this.crlFileLocateButton.Size = new System.Drawing.Size(24, 23);
            this.crlFileLocateButton.TabIndex = 5;
            this.crlFileLocateButton.Text = "...";
            this.crlFileLocateButton.Click += new System.EventHandler(this.crlFileLocateButton_Click);
            // 
            // crlFileTextBox
            // 
            this.crlFileTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.crlFileTextBox.Enabled = false;
            this.crlFileTextBox.Location = new System.Drawing.Point(120, 122);
            this.crlFileTextBox.Name = "crlFileTextBox";
            this.crlFileTextBox.Size = new System.Drawing.Size(512, 20);
            this.crlFileTextBox.TabIndex = 4;
            // 
            // label32
            // 
            this.label32.Location = new System.Drawing.Point(8, 122);
            this.label32.Name = "label32";
            this.label32.Size = new System.Drawing.Size(112, 23);
            this.label32.TabIndex = 3;
            this.label32.Text = "URI to CRL archive:";
            // 
            // includeCrlCheckBox
            // 
            this.includeCrlCheckBox.Location = new System.Drawing.Point(11, 86);
            this.includeCrlCheckBox.Name = "includeCrlCheckBox";
            this.includeCrlCheckBox.Size = new System.Drawing.Size(104, 24);
            this.includeCrlCheckBox.TabIndex = 2;
            this.includeCrlCheckBox.Text = "include CRL";
            this.includeCrlCheckBox.CheckedChanged += new System.EventHandler(this.includeCrlCheckBox_CheckedChanged);
            // 
            // injectXadesCInformationButton
            // 
            this.injectXadesCInformationButton.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.injectXadesCInformationButton.Location = new System.Drawing.Point(252, 193);
            this.injectXadesCInformationButton.Name = "injectXadesCInformationButton";
            this.injectXadesCInformationButton.Size = new System.Drawing.Size(172, 34);
            this.injectXadesCInformationButton.TabIndex = 1;
            this.injectXadesCInformationButton.Text = "Inject XAdES-C information";
            this.injectXadesCInformationButton.Click += new System.EventHandler(this.injectXadesCInformationButton_Click);
            // 
            // includeCertificateChainCheckBox
            // 
            this.includeCertificateChainCheckBox.Location = new System.Drawing.Point(11, 20);
            this.includeCertificateChainCheckBox.Name = "includeCertificateChainCheckBox";
            this.includeCertificateChainCheckBox.Size = new System.Drawing.Size(272, 24);
            this.includeCertificateChainCheckBox.TabIndex = 0;
            this.includeCertificateChainCheckBox.Text = "Include certificate chain";
            this.includeCertificateChainCheckBox.CheckedChanged += new System.EventHandler(this.includeCertificateChainCheckBox_CheckedChanged);
            // 
            // tabPage11
            // 
            this.tabPage11.Controls.Add(this.groupBox3);
            this.tabPage11.Location = new System.Drawing.Point(4, 22);
            this.tabPage11.Name = "tabPage11";
            this.tabPage11.Size = new System.Drawing.Size(688, 502);
            this.tabPage11.TabIndex = 9;
            this.tabPage11.Text = "XAdES-X";
            // 
            // groupBox3
            // 
            this.groupBox3.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox3.Controls.Add(this.label35);
            this.groupBox3.Controls.Add(this.xadesXTimeStampIdTextBox);
            this.groupBox3.Controls.Add(this.injectXadesXInformationButton);
            this.groupBox3.Controls.Add(this.refsOnlyTimeStampRadioButton);
            this.groupBox3.Controls.Add(this.sigAndRefsTimeStampRadioButton);
            this.groupBox3.Location = new System.Drawing.Point(8, 8);
            this.groupBox3.Name = "groupBox3";
            this.groupBox3.Size = new System.Drawing.Size(672, 184);
            this.groupBox3.TabIndex = 0;
            this.groupBox3.TabStop = false;
            this.groupBox3.Text = "Choose XAdES-X style";
            // 
            // label35
            // 
            this.label35.Location = new System.Drawing.Point(11, 79);
            this.label35.Name = "label35";
            this.label35.Size = new System.Drawing.Size(124, 23);
            this.label35.TabIndex = 4;
            this.label35.Text = "Xades-X timestamp Id:";
            // 
            // xadesXTimeStampIdTextBox
            // 
            this.xadesXTimeStampIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.xadesXTimeStampIdTextBox.Location = new System.Drawing.Point(141, 79);
            this.xadesXTimeStampIdTextBox.Name = "xadesXTimeStampIdTextBox";
            this.xadesXTimeStampIdTextBox.Size = new System.Drawing.Size(504, 20);
            this.xadesXTimeStampIdTextBox.TabIndex = 3;
            this.xadesXTimeStampIdTextBox.Text = "XadesXTimeStampId";
            // 
            // injectXadesXInformationButton
            // 
            this.injectXadesXInformationButton.Location = new System.Drawing.Point(261, 132);
            this.injectXadesXInformationButton.Name = "injectXadesXInformationButton";
            this.injectXadesXInformationButton.Size = new System.Drawing.Size(160, 36);
            this.injectXadesXInformationButton.TabIndex = 2;
            this.injectXadesXInformationButton.Text = "Inject XAdES-X information";
            this.injectXadesXInformationButton.Click += new System.EventHandler(this.injectXadesXInformationButton_Click);
            // 
            // refsOnlyTimeStampRadioButton
            // 
            this.refsOnlyTimeStampRadioButton.Location = new System.Drawing.Point(15, 40);
            this.refsOnlyTimeStampRadioButton.Name = "refsOnlyTimeStampRadioButton";
            this.refsOnlyTimeStampRadioButton.Size = new System.Drawing.Size(144, 24);
            this.refsOnlyTimeStampRadioButton.TabIndex = 1;
            this.refsOnlyTimeStampRadioButton.Text = "RefsOnlyTimeStamp";
            // 
            // sigAndRefsTimeStampRadioButton
            // 
            this.sigAndRefsTimeStampRadioButton.Checked = true;
            this.sigAndRefsTimeStampRadioButton.Location = new System.Drawing.Point(14, 19);
            this.sigAndRefsTimeStampRadioButton.Name = "sigAndRefsTimeStampRadioButton";
            this.sigAndRefsTimeStampRadioButton.Size = new System.Drawing.Size(144, 24);
            this.sigAndRefsTimeStampRadioButton.TabIndex = 0;
            this.sigAndRefsTimeStampRadioButton.TabStop = true;
            this.sigAndRefsTimeStampRadioButton.Text = "SigAndRefsTimeStamp";
            // 
            // tabPage12
            // 
            this.tabPage12.Controls.Add(this.groupBox17);
            this.tabPage12.Location = new System.Drawing.Point(4, 22);
            this.tabPage12.Name = "tabPage12";
            this.tabPage12.Size = new System.Drawing.Size(688, 502);
            this.tabPage12.TabIndex = 10;
            this.tabPage12.Text = "XAdES-XL";
            // 
            // groupBox17
            // 
            this.groupBox17.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox17.Controls.Add(this.includeRevocationValuesCheckBox);
            this.groupBox17.Controls.Add(this.includeCertificateValuesCheckBox);
            this.groupBox17.Controls.Add(this.label37);
            this.groupBox17.Controls.Add(this.revocationValuesIdTextBox);
            this.groupBox17.Controls.Add(this.certificateValuesIdTextBox);
            this.groupBox17.Controls.Add(this.label36);
            this.groupBox17.Controls.Add(this.injectXadesXLInformationButton);
            this.groupBox17.Location = new System.Drawing.Point(8, 8);
            this.groupBox17.Name = "groupBox17";
            this.groupBox17.Size = new System.Drawing.Size(672, 208);
            this.groupBox17.TabIndex = 0;
            this.groupBox17.TabStop = false;
            this.groupBox17.Text = "XAdES-XL";
            // 
            // includeRevocationValuesCheckBox
            // 
            this.includeRevocationValuesCheckBox.Location = new System.Drawing.Point(11, 82);
            this.includeRevocationValuesCheckBox.Name = "includeRevocationValuesCheckBox";
            this.includeRevocationValuesCheckBox.Size = new System.Drawing.Size(160, 24);
            this.includeRevocationValuesCheckBox.TabIndex = 6;
            this.includeRevocationValuesCheckBox.Text = "Include revocation values";
            this.includeRevocationValuesCheckBox.CheckedChanged += new System.EventHandler(this.includeRevocationValuesCheckBox_CheckedChanged);
            // 
            // includeCertificateValuesCheckBox
            // 
            this.includeCertificateValuesCheckBox.Location = new System.Drawing.Point(11, 21);
            this.includeCertificateValuesCheckBox.Name = "includeCertificateValuesCheckBox";
            this.includeCertificateValuesCheckBox.Size = new System.Drawing.Size(160, 24);
            this.includeCertificateValuesCheckBox.TabIndex = 5;
            this.includeCertificateValuesCheckBox.Text = "Include certficate values";
            this.includeCertificateValuesCheckBox.CheckedChanged += new System.EventHandler(this.includeCertificateValuesCheckBox_CheckedChanged);
            // 
            // label37
            // 
            this.label37.Location = new System.Drawing.Point(8, 112);
            this.label37.Name = "label37";
            this.label37.Size = new System.Drawing.Size(112, 23);
            this.label37.TabIndex = 4;
            this.label37.Text = "RevocationValuesId:";
            // 
            // revocationValuesIdTextBox
            // 
            this.revocationValuesIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.revocationValuesIdTextBox.Enabled = false;
            this.revocationValuesIdTextBox.Location = new System.Drawing.Point(120, 112);
            this.revocationValuesIdTextBox.Name = "revocationValuesIdTextBox";
            this.revocationValuesIdTextBox.Size = new System.Drawing.Size(544, 20);
            this.revocationValuesIdTextBox.TabIndex = 3;
            this.revocationValuesIdTextBox.Text = "RevocationValuesId";
            // 
            // certificateValuesIdTextBox
            // 
            this.certificateValuesIdTextBox.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.certificateValuesIdTextBox.Enabled = false;
            this.certificateValuesIdTextBox.Location = new System.Drawing.Point(120, 48);
            this.certificateValuesIdTextBox.Name = "certificateValuesIdTextBox";
            this.certificateValuesIdTextBox.Size = new System.Drawing.Size(544, 20);
            this.certificateValuesIdTextBox.TabIndex = 2;
            this.certificateValuesIdTextBox.Text = "CertificateValuesId";
            // 
            // label36
            // 
            this.label36.Location = new System.Drawing.Point(8, 51);
            this.label36.Name = "label36";
            this.label36.Size = new System.Drawing.Size(112, 23);
            this.label36.TabIndex = 1;
            this.label36.Text = "CertificateValuesId:";
            // 
            // injectXadesXLInformationButton
            // 
            this.injectXadesXLInformationButton.Location = new System.Drawing.Point(269, 158);
            this.injectXadesXLInformationButton.Name = "injectXadesXLInformationButton";
            this.injectXadesXLInformationButton.Size = new System.Drawing.Size(168, 34);
            this.injectXadesXLInformationButton.TabIndex = 0;
            this.injectXadesXLInformationButton.Text = "Inject XAdES-XL information";
            this.injectXadesXLInformationButton.Click += new System.EventHandler(this.injectXadesXLInformationButton_Click);
            // 
            // tabPage1
            // 
            this.tabPage1.Controls.Add(this.groupBox6);
            this.tabPage1.Controls.Add(this.groupBox1);
            this.tabPage1.Location = new System.Drawing.Point(4, 22);
            this.tabPage1.Name = "tabPage1";
            this.tabPage1.Size = new System.Drawing.Size(712, 542);
            this.tabPage1.TabIndex = 0;
            this.tabPage1.Text = "Verify signature ";
            // 
            // groupBox6
            // 
            this.groupBox6.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.groupBox6.Controls.Add(this.checkSelectionGroupBox);
            this.groupBox6.Controls.Add(this.verifyXmlRenderTree);
            this.groupBox6.Controls.Add(this.readOnlyNoCheckcheckBox);
            this.groupBox6.Controls.Add(this.label15);
            this.groupBox6.Controls.Add(this.label14);
            this.groupBox6.Controls.Add(this.signatureTypeLabel);
            this.groupBox6.Controls.Add(this.checkSignatureLabel);
            this.groupBox6.Controls.Add(this.checkSignatureButton);
            this.groupBox6.Location = new System.Drawing.Point(8, 56);
            this.groupBox6.Name = "groupBox6";
            this.groupBox6.Size = new System.Drawing.Size(696, 480);
            this.groupBox6.TabIndex = 9;
            this.groupBox6.TabStop = false;
            this.groupBox6.Text = "Check and display signature";
            // 
            // checkSelectionGroupBox
            // 
            this.checkSelectionGroupBox.Controls.Add(this.verify040000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify020000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify010000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.checkExplanationLabel);
            this.checkSelectionGroupBox.Controls.Add(this.verify000001CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify004000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000020CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000200CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000040CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000400CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000080CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000004CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify002000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify001000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000100CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000800CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000010CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify008000CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000002CheckBox);
            this.checkSelectionGroupBox.Controls.Add(this.verify000008CheckBox);
            this.checkSelectionGroupBox.Location = new System.Drawing.Point(224, 8);
            this.checkSelectionGroupBox.Name = "checkSelectionGroupBox";
            this.checkSelectionGroupBox.Size = new System.Drawing.Size(384, 80);
            this.checkSelectionGroupBox.TabIndex = 30;
            this.checkSelectionGroupBox.TabStop = false;
            this.checkSelectionGroupBox.Text = "Check selection";
            // 
            // verify040000CheckBox
            // 
            this.verify040000CheckBox.Checked = true;
            this.verify040000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify040000CheckBox.Location = new System.Drawing.Point(40, 48);
            this.verify040000CheckBox.Name = "verify040000CheckBox";
            this.verify040000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify040000CheckBox.TabIndex = 33;
            this.verify040000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify040000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify020000CheckBox
            // 
            this.verify020000CheckBox.Checked = true;
            this.verify020000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify020000CheckBox.Location = new System.Drawing.Point(56, 48);
            this.verify020000CheckBox.Name = "verify020000CheckBox";
            this.verify020000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify020000CheckBox.TabIndex = 32;
            this.verify020000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify020000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify010000CheckBox
            // 
            this.verify010000CheckBox.Checked = true;
            this.verify010000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify010000CheckBox.Location = new System.Drawing.Point(72, 48);
            this.verify010000CheckBox.Name = "verify010000CheckBox";
            this.verify010000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify010000CheckBox.TabIndex = 31;
            this.verify010000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify010000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // checkExplanationLabel
            // 
            this.checkExplanationLabel.Location = new System.Drawing.Point(8, 16);
            this.checkExplanationLabel.Name = "checkExplanationLabel";
            this.checkExplanationLabel.Size = new System.Drawing.Size(368, 32);
            this.checkExplanationLabel.TabIndex = 30;
            this.checkExplanationLabel.Text = "Hover over checkboxes to see explanation";
            this.checkExplanationLabel.TextAlign = System.Drawing.ContentAlignment.MiddleCenter;
            // 
            // verify000001CheckBox
            // 
            this.verify000001CheckBox.Checked = true;
            this.verify000001CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000001CheckBox.Location = new System.Drawing.Point(328, 48);
            this.verify000001CheckBox.Name = "verify000001CheckBox";
            this.verify000001CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000001CheckBox.TabIndex = 14;
            this.verify000001CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000001CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify004000CheckBox
            // 
            this.verify004000CheckBox.Checked = true;
            this.verify004000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify004000CheckBox.Location = new System.Drawing.Point(104, 48);
            this.verify004000CheckBox.Name = "verify004000CheckBox";
            this.verify004000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify004000CheckBox.TabIndex = 28;
            this.verify004000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify004000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000020CheckBox
            // 
            this.verify000020CheckBox.Checked = true;
            this.verify000020CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000020CheckBox.Location = new System.Drawing.Point(248, 48);
            this.verify000020CheckBox.Name = "verify000020CheckBox";
            this.verify000020CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000020CheckBox.TabIndex = 19;
            this.verify000020CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000020CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000200CheckBox
            // 
            this.verify000200CheckBox.Checked = true;
            this.verify000200CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000200CheckBox.Location = new System.Drawing.Point(184, 48);
            this.verify000200CheckBox.Name = "verify000200CheckBox";
            this.verify000200CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000200CheckBox.TabIndex = 23;
            this.verify000200CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000200CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000040CheckBox
            // 
            this.verify000040CheckBox.Checked = true;
            this.verify000040CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000040CheckBox.Location = new System.Drawing.Point(232, 48);
            this.verify000040CheckBox.Name = "verify000040CheckBox";
            this.verify000040CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000040CheckBox.TabIndex = 20;
            this.verify000040CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000040CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000400CheckBox
            // 
            this.verify000400CheckBox.Checked = true;
            this.verify000400CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000400CheckBox.Location = new System.Drawing.Point(168, 48);
            this.verify000400CheckBox.Name = "verify000400CheckBox";
            this.verify000400CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000400CheckBox.TabIndex = 24;
            this.verify000400CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000400CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000080CheckBox
            // 
            this.verify000080CheckBox.Checked = true;
            this.verify000080CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000080CheckBox.Location = new System.Drawing.Point(216, 48);
            this.verify000080CheckBox.Name = "verify000080CheckBox";
            this.verify000080CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000080CheckBox.TabIndex = 21;
            this.verify000080CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000080CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000004CheckBox
            // 
            this.verify000004CheckBox.Checked = true;
            this.verify000004CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000004CheckBox.Location = new System.Drawing.Point(296, 48);
            this.verify000004CheckBox.Name = "verify000004CheckBox";
            this.verify000004CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000004CheckBox.TabIndex = 16;
            this.verify000004CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000004CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify002000CheckBox
            // 
            this.verify002000CheckBox.Checked = true;
            this.verify002000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify002000CheckBox.Location = new System.Drawing.Point(120, 48);
            this.verify002000CheckBox.Name = "verify002000CheckBox";
            this.verify002000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify002000CheckBox.TabIndex = 27;
            this.verify002000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify002000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify001000CheckBox
            // 
            this.verify001000CheckBox.Checked = true;
            this.verify001000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify001000CheckBox.Location = new System.Drawing.Point(136, 48);
            this.verify001000CheckBox.Name = "verify001000CheckBox";
            this.verify001000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify001000CheckBox.TabIndex = 26;
            this.verify001000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify001000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000100CheckBox
            // 
            this.verify000100CheckBox.Checked = true;
            this.verify000100CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000100CheckBox.Location = new System.Drawing.Point(200, 48);
            this.verify000100CheckBox.Name = "verify000100CheckBox";
            this.verify000100CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000100CheckBox.TabIndex = 22;
            this.verify000100CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000100CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000800CheckBox
            // 
            this.verify000800CheckBox.Checked = true;
            this.verify000800CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000800CheckBox.Location = new System.Drawing.Point(152, 48);
            this.verify000800CheckBox.Name = "verify000800CheckBox";
            this.verify000800CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000800CheckBox.TabIndex = 25;
            this.verify000800CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000800CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000010CheckBox
            // 
            this.verify000010CheckBox.Checked = true;
            this.verify000010CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000010CheckBox.Location = new System.Drawing.Point(264, 48);
            this.verify000010CheckBox.Name = "verify000010CheckBox";
            this.verify000010CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000010CheckBox.TabIndex = 18;
            this.verify000010CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000010CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify008000CheckBox
            // 
            this.verify008000CheckBox.Checked = true;
            this.verify008000CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify008000CheckBox.Location = new System.Drawing.Point(88, 48);
            this.verify008000CheckBox.Name = "verify008000CheckBox";
            this.verify008000CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify008000CheckBox.TabIndex = 29;
            this.verify008000CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify008000CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000002CheckBox
            // 
            this.verify000002CheckBox.Checked = true;
            this.verify000002CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000002CheckBox.Location = new System.Drawing.Point(312, 48);
            this.verify000002CheckBox.Name = "verify000002CheckBox";
            this.verify000002CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000002CheckBox.TabIndex = 15;
            this.verify000002CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000002CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verify000008CheckBox
            // 
            this.verify000008CheckBox.Checked = true;
            this.verify000008CheckBox.CheckState = System.Windows.Forms.CheckState.Checked;
            this.verify000008CheckBox.Location = new System.Drawing.Point(280, 48);
            this.verify000008CheckBox.Name = "verify000008CheckBox";
            this.verify000008CheckBox.Size = new System.Drawing.Size(12, 24);
            this.verify000008CheckBox.TabIndex = 17;
            this.verify000008CheckBox.MouseEnter += new System.EventHandler(this.verifyCheckBox_MouseEnter);
            this.verify000008CheckBox.MouseLeave += new System.EventHandler(this.verify020000CheckBox_MouseLeave);
            // 
            // verifyXmlRenderTree
            // 
            this.verifyXmlRenderTree.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.verifyXmlRenderTree.Location = new System.Drawing.Point(8, 96);
            this.verifyXmlRenderTree.Name = "verifyXmlRenderTree";
            this.verifyXmlRenderTree.Size = new System.Drawing.Size(680, 376);
            this.verifyXmlRenderTree.TabIndex = 13;
            // 
            // readOnlyNoCheckcheckBox
            // 
            this.readOnlyNoCheckcheckBox.Location = new System.Drawing.Point(16, 16);
            this.readOnlyNoCheckcheckBox.Name = "readOnlyNoCheckcheckBox";
            this.readOnlyNoCheckcheckBox.Size = new System.Drawing.Size(144, 24);
            this.readOnlyNoCheckcheckBox.TabIndex = 11;
            this.readOnlyNoCheckcheckBox.Text = "display only, don\'t verify";
            this.readOnlyNoCheckcheckBox.CheckedChanged += new System.EventHandler(this.readOnlyNoCheckcheckBox_CheckedChanged);
            // 
            // label15
            // 
            this.label15.Location = new System.Drawing.Point(16, 72);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(128, 23);
            this.label15.TabIndex = 9;
            this.label15.Text = "Signature check returns:";
            // 
            // label14
            // 
            this.label14.Location = new System.Drawing.Point(16, 48);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(128, 23);
            this.label14.TabIndex = 8;
            this.label14.Text = "Signature standard:";
            // 
            // MainForm
            // 
            this.AutoScaleBaseSize = new System.Drawing.Size(5, 13);
            this.ClientSize = new System.Drawing.Size(736, 582);
            this.Controls.Add(this.tabControl1);
            this.Name = "MainForm";
            this.Text = "XAdES Test Client";
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.tabControl1.ResumeLayout(false);
            this.tabPage2.ResumeLayout(false);
            this.tabControl2.ResumeLayout(false);
            this.tabPage4.ResumeLayout(false);
            this.tabPage4.PerformLayout();
            this.tabPage3.ResumeLayout(false);
            this.groupBox15.ResumeLayout(false);
            this.groupBox14.ResumeLayout(false);
            this.tabPage5.ResumeLayout(false);
            this.groupBox13.ResumeLayout(false);
            this.groupBox13.PerformLayout();
            this.groupBox7.ResumeLayout(false);
            this.groupBox5.ResumeLayout(false);
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.tabPage6.ResumeLayout(false);
            this.groupBox10.ResumeLayout(false);
            this.groupBox10.PerformLayout();
            this.groupBox9.ResumeLayout(false);
            this.groupBox9.PerformLayout();
            this.groupBox11.ResumeLayout(false);
            this.groupBox11.PerformLayout();
            this.tabPage7.ResumeLayout(false);
            this.tabPage8.ResumeLayout(false);
            this.tabPage10.ResumeLayout(false);
            this.groupBox8.ResumeLayout(false);
            this.groupBox8.PerformLayout();
            this.tabPage9.ResumeLayout(false);
            this.groupBox4.ResumeLayout(false);
            this.groupBox4.PerformLayout();
            this.tabPage11.ResumeLayout(false);
            this.groupBox3.ResumeLayout(false);
            this.groupBox3.PerformLayout();
            this.tabPage12.ResumeLayout(false);
            this.groupBox17.ResumeLayout(false);
            this.groupBox17.PerformLayout();
            this.tabPage1.ResumeLayout(false);
            this.groupBox6.ResumeLayout(false);
            this.checkSelectionGroupBox.ResumeLayout(false);
            this.ResumeLayout(false);

		}
		#endregion

		/// <summary>
		/// The main entry point for the application.
		/// </summary>
		[STAThread]
		public static void Main() 
		{
			Application.Run(new MainForm());
		}

		#region Read and Verify Signature
		private void browseForFileToReadButton_Click(object sender, System.EventArgs e)
		{
			DialogResult dialogResult;
		
			dialogResult = this.openFileDialog.ShowDialog();
			if (dialogResult == DialogResult.OK)
			{
				this.signatureFileToReadTextBox.Text = this.openFileDialog.FileName;
			}
		}

		private XadesCheckSignatureMasks ComposeMask()
		{
			XadesCheckSignatureMasks retVal;

			retVal = 0;
			if (this.verify000001CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckXmldsigSignature;
			}
			if (this.verify000002CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.ValidateAgainstSchema;
			}
			if (this.verify000004CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckSameCertificate;
			}
			if (this.verify000008CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckAllReferencesExistInAllDataObjectsTimeStamp;
			}
			if (this.verify000010CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckAllHashDataInfosInIndividualDataObjectsTimeStamp;
			}
			if (this.verify000020CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckCounterSignatures;
			}
			if (this.verify000040CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckCounterSignaturesReference;
			}
			if (this.verify000080CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckObjectReferencesInCommitmentTypeIndication;
			}
			if (this.verify000100CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole;
			}
			if (this.verify000200CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue;
			}
			if (this.verify000400CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckQualifyingPropertiesTarget;
			}
			if (this.verify000800CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckQualifyingProperties;
			}
			if (this.verify001000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckSigAndRefsTimeStampHashDataInfos;
			}
			if (this.verify002000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckRefsOnlyTimeStampHashDataInfos;
			}
			if (this.verify004000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckArchiveTimeStampHashDataInfos;
			}
			if (this.verify008000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckXadesCIsXadesT;
			}
			if (this.verify010000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckXadesXLIsXadesX;
			}
			if (this.verify020000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckCertificateValuesMatchCertificateRefs;
			}
			if (this.verify040000CheckBox.Checked)
			{
				retVal |= XadesCheckSignatureMasks.CheckRevocationValuesMatchRevocationRefs;
			}

			return retVal;
		}

		private void checkSignatureButton_Click(object sender, System.EventArgs e)
		{
			XmlDocument xmlDocument;
			XmlNodeList signatureNodeList;
			XadesCheckSignatureMasks composedMask;
			bool checkResult;

			try
			{
				this.signatureTypeLabel.Text = "...";
				this.checkSignatureLabel.Text = "...";
				this.Refresh();

				xmlDocument = new XmlDocument();
				xmlDocument.PreserveWhitespace = true;
				xmlDocument.Load(this.signatureFileToReadTextBox.Text);

				this.xadesSignedXml = new XadesSignedXml(xmlDocument.DocumentElement); //Needed if it is a enveloped signature document
				signatureNodeList = xmlDocument.GetElementsByTagName("Signature");
				if (signatureNodeList.Count == 0)
				{
					signatureNodeList = xmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
				}
				this.xadesSignedXml.LoadXml((XmlElement)signatureNodeList[0]);
				if (!this.readOnlyNoCheckcheckBox.Checked)
				{
					composedMask = this.ComposeMask();
					checkResult = this.xadesSignedXml.XadesCheckSignature(composedMask);
					this.checkSignatureLabel.Text = checkResult.ToString();
					if (checkResult == false)
					{
						this.checkSignatureLabel.ForeColor = Color.Red;
					}
					else
					{
						this.checkSignatureLabel.ForeColor = Color.Black;
					}
				}
				this.signatureTypeLabel.Text = this.xadesSignedXml.SignatureStandard.ToString();
				this.verifyXmlRenderTree.RenderXmlNode(this.xadesSignedXml.GetXml());
			}
			catch (Exception exception)
			{
				this.signatureTypeLabel.Text = this.xadesSignedXml.SignatureStandard.ToString();
				if (exception.InnerException != null)
				{
					MessageBox.Show("Exception: " + exception.Message + " -> " + exception.InnerException.Message);
				}
				else
				{
					MessageBox.Show("Exception: " + exception.Message);
				}
			}
		}
		#endregion

		#region Create Signature

		#region Select document to sign
		private void envelopedSignatureDocumentLocateButton_Click(object sender, System.EventArgs e)
		{
			DialogResult dialogResult;

			this.openFileDialog.Filter = "XML files (*.xml)|*.xml|All files (*.*)|*.*";
			dialogResult = this.openFileDialog.ShowDialog();
			if (dialogResult == DialogResult.OK)
			{
				this.envelopingDocumentTextBox.Text = this.openFileDialog.FileName;
			}
		}

		private void addReferenceButton_Click(object sender, System.EventArgs e)
		{
			XmlDsigEnvelopedSignatureTransform xmlDsigEnvelopedSignatureTransform;
			Reference reference;
			
			reference = new Reference();
			if (this.envelopedSignatureRadioButton.Checked)
			{
				if (this.newSignatureCheckBox.Checked)
				{
					this.envelopedSignatureXmlDocument = new XmlDocument();
					this.documentDataObjectCounter = 1;
				}
				this.envelopedSignatureXmlDocument.PreserveWhitespace = true;
				this.envelopedSignatureXmlDocument.Load(this.envelopingDocumentTextBox.Text);
				this.xadesSignedXml = new XadesSignedXml(this.envelopedSignatureXmlDocument);

				reference.Uri = "";
				XmlDsigC14NTransform xmlDsigC14NTransform = new XmlDsigC14NTransform();
				reference.AddTransform(xmlDsigC14NTransform);
				xmlDsigEnvelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
				reference.AddTransform(xmlDsigEnvelopedSignatureTransform);
			}
			else
			{
				if (this.newSignatureCheckBox.Checked)
				{
					this.xadesSignedXml = new XadesSignedXml();
					this.documentDataObjectCounter = 1;
				}
				if (this.includedXmlRadioButton.Checked)
				{
					reference.Uri = "#" + this.objectIdPrefixTextBox.Text + this.documentDataObjectCounter.ToString();
					reference.Type = SignedXml.XmlDsigNamespaceUrl + "Object";

					//Add an object
					System.Security.Cryptography.Xml.DataObject dataObject = new System.Security.Cryptography.Xml.DataObject();
					XmlDocument xmlDocument = new XmlDocument();
					xmlDocument.PreserveWhitespace = true;
					xmlDocument.LoadXml(this.includedXmltextBox.Text);
					dataObject.Data = xmlDocument.ChildNodes;
					dataObject.Id = this.objectIdPrefixTextBox.Text + this.documentDataObjectCounter.ToString();
					this.xadesSignedXml.AddObject(dataObject);
				}
				else
				{
					reference.Uri = this.externalDocumentUrlTextBox.Text;
					if (reference.Uri.EndsWith(".xml") || reference.Uri.EndsWith(".XML")) 
					{
						reference.AddTransform(new XmlDsigC14NTransform());
					}
				}
			}
			this.xadesSignedXml.AddReference(reference);
			this.documentDataObjectCounter++;
			this.nextObjectIdSuffixLabel.Text = this.documentDataObjectCounter.ToString();
		}
		#endregion

		#region Select certificate
		private X509Certificate2 LetUserChooseCertificate()
		{            
            X509Certificate2 cert = null;

			try 
			{
		        // Open the store of personal certificates.
	            X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
	            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly );
            
			    X509Certificate2Collection collection = (X509Certificate2Collection) store.Certificates;
			    X509Certificate2Collection fcollection = (X509Certificate2Collection) collection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
			    X509Certificate2Collection scollection = X509Certificate2UI.SelectFromCollection(fcollection, "XAdES sample","Choose a certificate", X509SelectionFlag.SingleSelection);

				if (scollection != null && scollection.Count == 1)
				{
                    cert = scollection[0];

                    if (cert.HasPrivateKey == false)
				    {
					    MessageBox.Show("This certificate does not have a private key associated with it");
                        cert = null;
				    }
				}
			
                store.Close();
			}
		    catch (Exception)
			{
			    MessageBox.Show("Unable to get the private key");
                cert = null;
			}

            return cert;
		}

		private void AddCertificateInfoToSignature()
		{
            RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider) this.Certificate.PrivateKey;
            this.xadesSignedXml.SigningKey = rsaKey;

            KeyInfo keyInfo = new KeyInfo();
			keyInfo.AddClause(new KeyInfoX509Data((X509Certificate) this.Certificate));
			if (this.includeKeyValueCheckBox.Checked)
			{
                keyInfo.AddClause(new RSAKeyValue(rsaKey));
			}

			this.xadesSignedXml.KeyInfo = keyInfo;
		}

		private void selectCertificateButton_Click(object sender, System.EventArgs e)
		{
            this.Certificate = this.LetUserChooseCertificate();
			if (this.Certificate != null)
			{
                this.Chain = new X509Chain();

                this.Chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                this.Chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                this.Chain.ChainPolicy.UrlRetrievalTimeout = new TimeSpan(0, 0, 30);
                this.Chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                if (this.Chain.Build(this.Certificate) == true)
                {
					this.certificateInfoIssuedLabel.Text = this.Certificate.SubjectName.Name;
					this.certificateInfoIssuerLabel.Text = this.Certificate.IssuerName.Name;
					this.issuerSerialLabel.Text = this.Certificate.SerialNumber;
					this.AddCertificateInfoToSignature();

                    this.issuerSerialLabel.Text = this.Certificate.SerialNumber;
                    this.issuerNameLabel.Text = this.Certificate.IssuerName.Name;
					this.digestMethodLabel.Text = SignedXml.XmlDsigSHA1Url;
					this.digestValueLabel.Text = this.Certificate.Thumbprint;

                    this.viewCertificateButton.Enabled = true;
				}
				else
				{
					this.Certificate = null;
                    this.Chain = null;
					MessageBox.Show("Certificate chain status isn't verified");
				}
			}
		}
		#endregion

		#region Add XAdES object
		private string ConvertHexToBase10(string hexString)
		{
			string buffer;
			UInt64 high;
			UInt64 mid;
			UInt64 low;
			UInt64 remainderToAddToMid;
			UInt64 remainderToAddToLow;
			string retVal = "";

			if (hexString.Length > 36)
			{
				throw new OverflowException("Maximum 18 bytes");
			}
			buffer = hexString.PadLeft(36, '0');
			low = UInt64.Parse(buffer.Substring(24, 12), System.Globalization.NumberStyles.HexNumber);
			mid = UInt64.Parse(buffer.Substring(12, 12), System.Globalization.NumberStyles.HexNumber);
			high = UInt64.Parse(buffer.Substring(0, 12), System.Globalization.NumberStyles.HexNumber);

			while ((low != 0) || (mid != 0) || (high != 0))
			{
				remainderToAddToMid = (high%10)*0x1000000000000;
				mid += remainderToAddToMid;
				remainderToAddToLow = (mid%10)*0x1000000000000;
				low += remainderToAddToLow;
				retVal = (low%10).ToString() + retVal;
				high /= 10;
				mid /= 10;
				low /= 10;
			}

			return retVal;
		}

		private void AddSignedSignatureProperties(SignedSignatureProperties signedSignatureProperties, SignedDataObjectProperties signedDataObjectProperties,
			UnsignedSignatureProperties unsignedSignatureProperties)
		{
			XmlDocument xmlDocument;
			Cert cert;

			xmlDocument = new XmlDocument();

			cert = new Cert();
            cert.IssuerSerial.X509IssuerName = this.Certificate.IssuerName.Name;
			cert.IssuerSerial.X509SerialNumber = this.Certificate.SerialNumber;
			cert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
            cert.CertDigest.DigestValue = this.Certificate.GetCertHash();
			signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);

			signedSignatureProperties.SigningTime = DateTime.Parse(this.signingTimeTextBox.Text);

			signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = true;

			if (this.includeSignatureProductionPlaceCheckBox.Checked)
			{
				signedSignatureProperties.SignatureProductionPlace.City = this.signatureCityTextBox.Text;
				signedSignatureProperties.SignatureProductionPlace.StateOrProvince = this.signatureStateOrProvinceTextBox.Text;
				signedSignatureProperties.SignatureProductionPlace.PostalCode = this.signaturePostalCodeTextBox.Text;
				signedSignatureProperties.SignatureProductionPlace.CountryName = this.signatureCountryNameTextBox.Text;
			}

			if (this.includeSignerRoleCheckBox.Checked)
			{
				ClaimedRole newClaimedRole = new ClaimedRole();

				xmlDocument.LoadXml(this.claimedRoleTextBox.Text);
				newClaimedRole.AnyXmlElement = (XmlElement)xmlDocument.FirstChild;
				signedSignatureProperties.SignerRole.ClaimedRoles.ClaimedRoleCollection.Add(newClaimedRole);
			}

			if (this.includeCommitmentTypeIndicationCheckBox.Checked)
			{
				CommitmentTypeIndication newCommitmentTypeIndication = new CommitmentTypeIndication(); 

				newCommitmentTypeIndication.CommitmentTypeId.Identifier.IdentifierUri = this.commitmentTypeIdentifierURITextBox.Text;
				switch (this.commitmentTypeIndicatorQualifierComboBox.Text)
				{
					case "":
						newCommitmentTypeIndication.CommitmentTypeId.Identifier.Qualifier = KnownQualifier.Uninitalized;
						break;
					case "OIDAsURI":
						newCommitmentTypeIndication.CommitmentTypeId.Identifier.Qualifier = KnownQualifier.OIDAsURI;
						break;
					case "OIDAsURN":
						newCommitmentTypeIndication.CommitmentTypeId.Identifier.Qualifier = KnownQualifier.OIDAsURN;
						break;
				}
				newCommitmentTypeIndication.CommitmentTypeId.Description = this.commitmentTypeIndicationIdTextBox.Text;
				newCommitmentTypeIndication.AllSignedDataObjects = true;

				signedDataObjectProperties.CommitmentTypeIndicationCollection.Add(newCommitmentTypeIndication);
			}

			if (this.includeDataObjectFormatCheckBox.Checked)
			{
				DataObjectFormat newDataObjectFormat = new DataObjectFormat();
			
				newDataObjectFormat.Description = this.dataObjectDescriptionTextBox.Text;
				newDataObjectFormat.MimeType = this.dataObjectFormatMimetypeTextBox.Text;
				newDataObjectFormat.ObjectReferenceAttribute = this.dataObjectReferenceTextBox.Text;
				signedDataObjectProperties.DataObjectFormatCollection.Add(newDataObjectFormat);
			}
		}

		private void addXadesInfoButton_Click(object sender, System.EventArgs e)
		{
			try
			{
				this.xadesSignedXml.Signature.Id = this.signatureIdTextBox.Text;
				XadesObject xadesObject = new XadesObject();
				xadesObject.Id = "XadesObject";
				xadesObject.QualifyingProperties.Target = "#" + this.signatureIdTextBox.Text;
				this.AddSignedSignatureProperties(
					xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties,
					xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties,
					xadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties);

				this.xadesSignedXml.AddXadesObject(xadesObject);
			}
			catch (Exception exception)
			{
				MessageBox.Show("Error occurred: " + exception.ToString());
			}
		}
		#endregion

		#region Compute and Show Signature
		private void computeSignatureButton_Click(object sender, System.EventArgs e)
		{
			try
			{
				this.xadesSignedXml.ComputeSignature();
				this.xadesSignedXml.SignatureValueId = this.signatureValueIdTextBox.Text;
				this.ShowSignature();
			}
			catch (Exception exception)
			{
				MessageBox.Show("Problem during signature computation (Did you select a valid certificate?): " + exception.Message);
			}
		}

		private void ShowSignature()
		{
			ViewSignatureForm viewSignatureForm;
			XmlElement xmlElementToShow;

			if (this.envelopedSignatureRadioButton.Checked)
			{
				this.envelopedSignatureXmlDocument.DocumentElement.AppendChild(this.envelopedSignatureXmlDocument.ImportNode(this.xadesSignedXml.GetXml(), true));
				xmlElementToShow = this.envelopedSignatureXmlDocument.DocumentElement;
			}
			else
			{
				xmlElementToShow = this.xadesSignedXml.GetXml();
			}
			viewSignatureForm = new ViewSignatureForm();
			viewSignatureForm.ShowSignature(this.xadesSignedXml.SignatureStandard, xmlElementToShow);
			viewSignatureForm.ShowDialog();
		}
		#endregion

		#region Counter Signature
		private void addCounterSignatureButton_Click(object sender, System.EventArgs e)
		{
            X509Certificate2 certificateForCounterSignature = this.LetUserChooseCertificate();
            if (certificateForCounterSignature != null)
			{
				this.xadesSignedXml.SignatureValueId = this.signatureValueIdTextBox.Text;

                XmlElement parentSignatureXmlElement = this.xadesSignedXml.GetXml();
                XmlDocument parentSignatureXmlDocument = new XmlDocument();
				parentSignatureXmlDocument.AppendChild(parentSignatureXmlDocument.ImportNode(parentSignatureXmlElement, true));

                XadesSignedXml counterSignature = new XadesSignedXml(parentSignatureXmlDocument);
                RSACryptoServiceProvider rsaKey = (RSACryptoServiceProvider) this.Certificate.PrivateKey;
                counterSignature.SigningKey = rsaKey;

                KeyInfo keyInfo = new KeyInfo();
                keyInfo.AddClause(new KeyInfoX509Data((X509Certificate) certificateForCounterSignature));
                keyInfo.AddClause(new RSAKeyValue(rsaKey));
				counterSignature.KeyInfo = keyInfo;

				Cert cert = new Cert();
                cert.IssuerSerial.X509IssuerName = certificateForCounterSignature.IssuerName.Name;
                cert.IssuerSerial.X509SerialNumber = certificateForCounterSignature.SerialNumber;
				cert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
                cert.CertDigest.DigestValue = certificateForCounterSignature.GetCertHash();

				counterSignature.Signature.Id = "CounterSignatureId";
                XadesObject counterSignatureXadesObject = new XadesObject();
				counterSignatureXadesObject.Id = "CounterSignatureXadesObjectId";
				counterSignatureXadesObject.QualifyingProperties.Target = "#CounterSignatureId";
				counterSignatureXadesObject.QualifyingProperties.SignedProperties.Id = "CounterSignatureSignedProperiesId";

				Reference newReference = new Reference();
				newReference.Uri = "#" + this.xadesSignedXml.SignatureValueId;
				counterSignature.AddReference(newReference);

                SignedSignatureProperties signedSignatureProperties = counterSignatureXadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties;
                signedSignatureProperties.SigningCertificate.CertCollection.Add(cert);
				signedSignatureProperties.SigningTime = DateTime.Parse(this.signingTimeTextBox.Text);
				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = true;
				counterSignature.AddXadesObject(counterSignatureXadesObject);

				counterSignature.ComputeSignature();

				UnsignedProperties unsignedProperties = this.xadesSignedXml.UnsignedProperties;
				unsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection.Add(counterSignature);
				this.xadesSignedXml.UnsignedProperties = unsignedProperties;

				this.ShowSignature();
			}
		}
		#endregion

		#region XAdES-T
		private void requestTimeStampButton_Click(object sender, System.EventArgs e)
		{
			TimeStamp signatureTimeStamp;
			HttpTsaClient httpTSAClient;
			KnownTsaResponsePkiStatus tsaResponsePkiStatus;
			ArrayList signatureValueElementXpaths;
			byte[] signatureValueHash;

			if (this.xadesSignedXml.SignatureStandard == KnownSignatureStandard.Xades)
			{
				try
				{
					httpTSAClient = new HttpTsaClient();
					httpTSAClient.RequestTsaCertificate = this.tsaCertificateInResponseCheckBox.Checked;
					signatureValueElementXpaths = new ArrayList();
					signatureValueElementXpaths.Add("ds:SignatureValue");
					ArrayList elementIdValues = new ArrayList();
					signatureValueHash = httpTSAClient.ComputeHashValueOfElementList(this.xadesSignedXml.GetXml(), signatureValueElementXpaths, ref elementIdValues);
					httpTSAClient.SendTsaWebRequest(this.tsaUriTextBox.Text, signatureValueHash);
					tsaResponsePkiStatus = httpTSAClient.ParseTsaResponse();
					if (tsaResponsePkiStatus == KnownTsaResponsePkiStatus.Granted)
					{
						signatureTimeStamp = new TimeStamp("SignatureTimeStamp");
						signatureTimeStamp.EncapsulatedTimeStamp.Id = this.signatureTimeStampIdTextBox.Text;
						signatureTimeStamp.EncapsulatedTimeStamp.PkiData = httpTSAClient.TsaTimeStamp;
						HashDataInfo hashDataInfo = new HashDataInfo();
						hashDataInfo.UriAttribute = "#" + elementIdValues[0];
						signatureTimeStamp.HashDataInfoCollection.Add(hashDataInfo);
						UnsignedProperties unsignedProperties = this.xadesSignedXml.UnsignedProperties;
						unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Add(signatureTimeStamp);
						this.xadesSignedXml.UnsignedProperties = unsignedProperties;

                        XmlElement xml = this.xadesSignedXml.XadesObject.GetXml();
                        XmlElement xml1 = this.xadesSignedXml.GetXml();

						this.ShowSignature();
					}
					else
					{
						MessageBox.Show("TSA timestamp request not granted: " + tsaResponsePkiStatus.ToString());
					}
				}
				catch (Exception exception)
				{
					MessageBox.Show("Exception occurred during TSA timestamp request: " + exception.ToString());
				}
			}
			else
			{
				MessageBox.Show("Signature standard should be XAdES. (You need to add XAdES info before computing the signature to be able to inject a timestamp)");
			}
		}
		#endregion

		#region XAdES-C
		private void crlFileLocateButton_Click(object sender, System.EventArgs e)
		{
			DialogResult dialogResult;

			this.openFileDialog.Filter = "Certificate Revocation List files (*.crl)|*.crl|All files (*.*)|*.*";
			dialogResult = this.openFileDialog.ShowDialog();
			if (dialogResult == DialogResult.OK)
			{
				this.crlFileTextBox.Text = this.openFileDialog.FileName;
			}
		}

		private byte[] GetFileBytes(string filename)
		{
			Stream fileStream;
			byte[] retVal;

			fileStream = File.OpenRead(filename);
			retVal = new byte[fileStream.Length];
			fileStream.Read(retVal, 0, retVal.Length);
			fileStream.Close();

			return retVal;
		}

		private void injectXadesCInformationButton_Click(object sender, System.EventArgs e)
		{
			UnsignedProperties unsignedProperties = null;
			Cert chainCert = null;
			SHA1 sha1Managed;
			byte[] crlDigest;
			CRLRef incCRLRef;

			if (this.includeCertificateChainCheckBox.Checked)
			{
				if (this.Chain != null)
				{
					unsignedProperties = this.xadesSignedXml.UnsignedProperties;
					unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs();

                    foreach (X509ChainElement element in this.Chain.ChainElements)
                    {
                        chainCert = new Cert();
                        chainCert.IssuerSerial.X509IssuerName = element.Certificate.IssuerName.Name;
                        chainCert.IssuerSerial.X509SerialNumber = element.Certificate.SerialNumber;
                        chainCert.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
                        chainCert.CertDigest.DigestValue = this.Certificate.GetCertHash();
                        unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.Id = this.completeCertificateRefsTextBox.Text;
                        unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection.Add(chainCert);
                    }

					this.xadesSignedXml.UnsignedProperties = unsignedProperties;
				}
				else
				{
					MessageBox.Show("The certificate chain was not accepted, can't add certificate chain information to CompleteCertificateRefs element");
				}
			}

			if (this.includeCrlCheckBox.Checked)
			{ //In this sample we will load the CRL from file on a CRL archive.
				Stream crlStream = File.OpenRead(this.crlFileTextBox.Text);
				sha1Managed = new SHA1Managed();
				crlDigest = sha1Managed.ComputeHash(crlStream);
				crlStream.Close();
								
				incCRLRef = new CRLRef();
                incCRLRef.CertDigest.DigestMethod.Algorithm = SignedXml.XmlDsigSHA1Url;
                incCRLRef.CertDigest.DigestValue = crlDigest;
                incCRLRef.CRLIdentifier.UriAttribute = this.crlFileTextBox.Text;

				Asn1Parser asn1Parser;
				asn1Parser = new Asn1Parser();
				asn1Parser.ParseAsn1(this.GetFileBytes(this.crlFileTextBox.Text));
				XmlNode searchXmlNode;
				searchXmlNode = asn1Parser.ParseTree.SelectSingleNode("//Universal_Constructed_Sequence/Universal_Constructed_Sequence/Universal_Constructed_Sequence/Universal_Constructed_Set/Universal_Constructed_Sequence/Universal_Primitive_PrintableString");
				if (searchXmlNode != null)
				{
                    incCRLRef.CRLIdentifier.Issuer = searchXmlNode.Attributes["Value"].Value;
				}
				else
				{
					throw new Exception("Parse error TSA response: can't find Issuer in CRL");
				}
				searchXmlNode = asn1Parser.ParseTree.SelectSingleNode("//Universal_Constructed_Sequence/Universal_Constructed_Sequence/Universal_Primitive_UtcTime");
				if (searchXmlNode != null)
				{
                    incCRLRef.CRLIdentifier.IssueTime = DateTime.Parse(searchXmlNode.Attributes["Value"].Value);
				}
				else
				{
					throw new Exception("Parse error TSA response: can't find IssueTime in CRL");
				}

				unsignedProperties = this.xadesSignedXml.UnsignedProperties;
				unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs = new CompleteRevocationRefs();
				unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.Id = this.completeRevocationRefsIdTextBox.Text;
                unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection.Add(incCRLRef);
				this.xadesSignedXml.UnsignedProperties = unsignedProperties;
			}

			if (this.includeCrlCheckBox.Checked || this.includeCertificateChainCheckBox.Checked)
			{
				this.ShowSignature();
			}
		}
		#endregion

		#region XAdES-X
		private void injectXadesXInformationButton_Click(object sender, System.EventArgs e)
		{
			TimeStamp xadesXTimeStamp;
			HttpTsaClient httpTSAClient;
			KnownTsaResponsePkiStatus tsaResponsePkiStatus;
			ArrayList signatureValueElementXpaths;
			ArrayList elementIdValues;
			byte[] signatureValueHash;
			HashDataInfo hashDataInfo;

			httpTSAClient = new HttpTsaClient();
			httpTSAClient.RequestTsaCertificate = this.tsaCertificateInResponseCheckBox.Checked;
			signatureValueElementXpaths = new ArrayList();
			if (this.sigAndRefsTimeStampRadioButton.Checked)
			{
				signatureValueElementXpaths.Add("ds:SignatureValue");
				signatureValueElementXpaths.Add("ds:Object/xsd:QualifyingProperties/xsd:UnsignedProperties/xsd:UnsignedSignatureProperties/xsd:SignatureTimeStamp/xsd:EncapsulatedTimeStamp");
				signatureValueElementXpaths.Add("ds:Object/xsd:QualifyingProperties/xsd:UnsignedProperties/xsd:UnsignedSignatureProperties/xsd:CompleteCertificateRefs");
				signatureValueElementXpaths.Add("ds:Object/xsd:QualifyingProperties/xsd:UnsignedProperties/xsd:UnsignedSignatureProperties/xsd:CompleteRevocationRefs");
			}
			else
			{
				signatureValueElementXpaths.Add("ds:Object/xsd:QualifyingProperties/xsd:UnsignedProperties/xsd:UnsignedSignatureProperties/xsd:CompleteCertificateRefs");
				signatureValueElementXpaths.Add("ds:Object/xsd:QualifyingProperties/xsd:UnsignedProperties/xsd:UnsignedSignatureProperties/xsd:CompleteRevocationRefs");
			}
			elementIdValues = new ArrayList();
			signatureValueHash = httpTSAClient.ComputeHashValueOfElementList(this.xadesSignedXml.GetXml(), signatureValueElementXpaths, ref elementIdValues);
			httpTSAClient.SendTsaWebRequest(this.tsaUriTextBox.Text, signatureValueHash);
			tsaResponsePkiStatus = httpTSAClient.ParseTsaResponse();
			if (tsaResponsePkiStatus == KnownTsaResponsePkiStatus.Granted)
			{
				if (this.sigAndRefsTimeStampRadioButton.Checked)
				{
					xadesXTimeStamp = new TimeStamp("SigAndRefsTimeStamp");
				}
				else
				{
					xadesXTimeStamp = new TimeStamp("RefsOnlyTimeStamp");
				}
				xadesXTimeStamp.EncapsulatedTimeStamp.PkiData = httpTSAClient.TsaTimeStamp;
				xadesXTimeStamp.EncapsulatedTimeStamp.Id = this.xadesXTimeStampIdTextBox.Text;

				foreach (string elementIdValue in elementIdValues)
				{
					hashDataInfo = new HashDataInfo();
					hashDataInfo.UriAttribute = "#" + elementIdValue;
					xadesXTimeStamp.HashDataInfoCollection.Add(hashDataInfo);
				}
				UnsignedProperties unsignedProperties = this.xadesSignedXml.UnsignedProperties;
				if (this.sigAndRefsTimeStampRadioButton.Checked)
				{
					unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = false;
					unsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection.Add(xadesXTimeStamp);
				}
				else
				{
					unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = true;
					unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampCollection.Add(xadesXTimeStamp);
				}
				this.xadesSignedXml.UnsignedProperties = unsignedProperties;
				this.ShowSignature();
			}
			else
			{
				MessageBox.Show("TSA timestamp request not granted: " + tsaResponsePkiStatus.ToString());
			}
		}
		#endregion

		#region XAdES-XL
		private void injectXadesXLInformationButton_Click(object sender, System.EventArgs e)
		{
			UnsignedProperties unsignedProperties = null;
			int certificateValuesCounter;
			CertificateValues certificateValues;
			EncapsulatedX509Certificate encapsulatedX509Certificate;
			RevocationValues revocationValues;
			CRLValue newCRLValue;

			if (this.includeCertificateValuesCheckBox.Checked)
			{
				if (this.Chain != null)
				{
					unsignedProperties = this.xadesSignedXml.UnsignedProperties;
					unsignedProperties.UnsignedSignatureProperties.CertificateValues = new CertificateValues();
					certificateValues = unsignedProperties.UnsignedSignatureProperties.CertificateValues;
					certificateValues.Id = this.certificateValuesIdTextBox.Text;
					certificateValuesCounter = 0;

                    foreach (X509ChainElement element in this.Chain.ChainElements)
                    {
                        encapsulatedX509Certificate = new EncapsulatedX509Certificate();
                        encapsulatedX509Certificate.Id = this.certificateValuesIdTextBox.Text + certificateValuesCounter.ToString();
                        encapsulatedX509Certificate.PkiData = element.Certificate.GetRawCertData();
                        certificateValuesCounter++;
                        certificateValues.EncapsulatedX509CertificateCollection.Add(encapsulatedX509Certificate);
                    }

					this.xadesSignedXml.UnsignedProperties = unsignedProperties;
				}
				else
				{
					MessageBox.Show("To add certificates, you need to add certificate references (XAdES-C) first");
				}
			}

			if (this.includeRevocationValuesCheckBox.Checked)
			{
				unsignedProperties = this.xadesSignedXml.UnsignedProperties;
				unsignedProperties.UnsignedSignatureProperties.RevocationValues = new RevocationValues();
				revocationValues = unsignedProperties.UnsignedSignatureProperties.RevocationValues;
				revocationValues.Id = this.revocationValuesIdTextBox.Text;
				newCRLValue = new CRLValue();
				newCRLValue.PkiData = this.GetFileBytes(this.crlFileTextBox.Text);
				revocationValues.CRLValues.CRLValueCollection.Add(newCRLValue);
				this.xadesSignedXml.UnsignedProperties = unsignedProperties;
				if (this.includeCertificateValuesCheckBox.Checked || this.includeRevocationValuesCheckBox.Checked)
				{
					this.ShowSignature();
				}
			}
		}
		#endregion

		#endregion

		#region UI operations
        private void viewCertificateButton_Click(object sender, EventArgs e)
        {
            if (this.Certificate != null)
            {
                X509Certificate2UI.DisplayCertificate(this.Certificate);
            }
        }

		private void externalDocumentRadioButton_CheckedChanged(object sender, System.EventArgs e)
		{
			if (((RadioButton)sender).Checked)
			{
				this.externalDocumentUrlTextBox.Enabled = true;
			}
			else
			{
				this.externalDocumentUrlTextBox.Enabled = false;
			}
		}

		private void includedXmlRadioButton_CheckedChanged(object sender, System.EventArgs e)
		{
			if (((RadioButton)sender).Checked)
			{
				this.includedXmltextBox.Enabled = true;
			}
			else
			{
				this.includedXmltextBox.Enabled = false;
			}
		}

		private void envelopedSignatureRadioButton_CheckedChanged(object sender, System.EventArgs e)
		{
			if (((RadioButton)sender).Checked)
			{
				this.envelopingDocumentTextBox.Enabled = true;
				this.envelopedSignatureDocumentLocateButton.Enabled = true;
			}
			else
			{
				this.envelopingDocumentTextBox.Enabled = false;
				this.envelopedSignatureDocumentLocateButton.Enabled = false;
			}		
		}

		private void includeSignatureProductionPlaceCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.signaturePostalCodeTextBox.Enabled = this.includeSignatureProductionPlaceCheckBox.Checked;
			this.signatureCityTextBox.Enabled = this.includeSignatureProductionPlaceCheckBox.Checked;
			this.signatureStateOrProvinceTextBox.Enabled = this.includeSignatureProductionPlaceCheckBox.Checked;
			this.signatureCountryNameTextBox.Enabled = this.includeSignatureProductionPlaceCheckBox.Checked;
		}

		private void includeSignerRoleCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.claimedRoleTextBox.Enabled = this.includeSignerRoleCheckBox.Checked;
		}

		private void includeCommitmentTypeIndicationCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.commitmentTypeIdentifierURITextBox.Enabled = this.includeCommitmentTypeIndicationCheckBox.Checked;
			this.commitmentTypeIndicatorQualifierComboBox.Enabled = this.includeCommitmentTypeIndicationCheckBox.Checked;
			this.commitmentTypeIndicationIdTextBox.Enabled = this.includeCommitmentTypeIndicationCheckBox.Checked;
		}

		private void includeDataObjectFormatCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.dataObjectDescriptionTextBox.Enabled = this.includeDataObjectFormatCheckBox.Checked;
			this.dataObjectFormatMimetypeTextBox.Enabled = this.includeDataObjectFormatCheckBox.Checked;
			this.dataObjectReferenceTextBox.Enabled = this.includeDataObjectFormatCheckBox.Checked;
		}

		private void includeCrlCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.crlFileLocateButton.Enabled = this.includeCrlCheckBox.Checked;
			this.crlFileTextBox.Enabled = this.includeCrlCheckBox.Checked;
			this.completeRevocationRefsIdTextBox.Enabled = this.includeCrlCheckBox.Checked;
		}

		private void includeCertificateChainCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.completeCertificateRefsTextBox.Enabled = this.includeCertificateChainCheckBox.Checked;
		}

		private void includeCertificateValuesCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.certificateValuesIdTextBox.Enabled = this.includeCertificateValuesCheckBox.Checked;
		}

		private void includeRevocationValuesCheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.revocationValuesIdTextBox.Enabled = this.includeRevocationValuesCheckBox.Checked;		
		}
		
		private void readOnlyNoCheckcheckBox_CheckedChanged(object sender, System.EventArgs e)
		{
			this.checkSelectionGroupBox.Enabled = !this.readOnlyNoCheckcheckBox.Checked;
		}

		private void verifyCheckBox_MouseEnter(object sender, System.EventArgs e)
		{
			string checkBoxName;
			ulong checkValue;
			
			checkBoxName = ((CheckBox)sender).Name;
			checkValue = Convert.ToUInt64(checkBoxName.Substring(6, 6), 16);
			this.checkExplanationLabel.Text = ((XadesCheckSignatureMasks)checkValue).ToString();
		}

		private void verify020000CheckBox_MouseLeave(object sender, System.EventArgs e)
		{
			this.checkExplanationLabel.Text = "Hover over checkboxes to see explanation";
		}
		#endregion
	}
}
