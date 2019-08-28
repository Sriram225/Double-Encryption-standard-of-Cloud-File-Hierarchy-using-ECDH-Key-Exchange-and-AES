using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using System.Data;
using System.Data.SqlClient;
using System.Configuration;
using System.Net.Mail;



public partial class Upload_File : System.Web.UI.Page
{
    public int i, j, k;
    protected void Page_Load(object sender, EventArgs e)
    {
        if (Session["a_id"] == "")
        {
            Response.Redirect("Login.aspx?msg=logout");

        }
    }
    protected void btnSave_Click(object sender, EventArgs e)
    {
        if (FileUpload1.HasFile)
        {

            string fileName = Path.GetFileNameWithoutExtension(FileUpload1.PostedFile.FileName);
            string fileExtension = Path.GetExtension(FileUpload1.PostedFile.FileName);
            string file_path = Path.GetFileName(FileUpload1.PostedFile.FileName);

            //Build the File Path for the original (input) and the encrypted (output) file.
            string input = Server.MapPath("../Files/") + fileName + fileExtension;
            string file_name1 = fileName + "_enc1" + fileExtension;
            string file_name2 = fileName + "_enc2" + fileExtension;
            string file_name3 = fileName + "_enc3" + fileExtension;
            string output1 = Server.MapPath("../Files/" + file_name1);
            string output2 = Server.MapPath("../Files/" + file_name2);
            string output3 = Server.MapPath("../Files/" + file_name3);

            string output = Server.MapPath("../Files/") + fileName + "_enc1" + fileExtension;
            //Save the Input File, Encrypt it and save the encrypted file in output path.
            FileUpload1.SaveAs(input);

            //SqlDataAdapter _adp_R = new SqlDataAdapter("select Top(1)* from auto_keys order by NEWID()", Database.cs);
            //DataTable _dtr = new DataTable();
            //_adp_R.Fill(_dtr);
            //string encryptedkey;
            //if (_dtr.Rows.Count > 0)
            //{
            //    encryptedkey = _dtr.Rows[0]["key_value"].ToString();
            //}
            //else
            //{
            //    encryptedkey = "0";
            //}

            string allowedChars = "";

            allowedChars = "a,b,c,d,e,f,g,h,i,j,k,l,m,n,o,p,q,r,s,t,u,v,w,x,y,z,";

            allowedChars += "A,B,C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z,";

            allowedChars += "1,2,3,4,5,6,7,8,9,0";

            char[] sep = { ',' };
            string[] arr = allowedChars.Split(sep);
            string encryptedkey = "";
            string temp = "";
            Random rand = new Random();
            for (int i = 0; i < 16; i++)
            {
                temp = arr[rand.Next(0, arr.Length)];
                encryptedkey += temp;
            }

            string key1 = encryptedkey;
            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(key1);

            Stream inputStream = FileUpload1.PostedFile.InputStream;
            Byte[] data;
            using (var streamReader = new MemoryStream())
            {
                inputStream.CopyTo(streamReader);
                data = streamReader.ToArray();
            }

            byte[] bobPrivateKey;
            byte[] iv;
            using (var alice = new ECDiffieHellmanCng())
            {
                byte[] encryptedMessage;

                alice.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                alice.HashAlgorithm = CngAlgorithm.Sha256;
                Alice.alicePublicKey = alice.PublicKey.ToByteArray();
                var bob = new Bob();
                CngKey k = CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] aliceKey =
                    alice.DeriveKeyMaterial(CngKey.Import(bob.bobPublicKey, CngKeyBlobFormat.EccPublicBlob));
                Alice.Send(aliceKey, data, out encryptedMessage, out iv);
                bobPrivateKey = bob.bobKey;
                //  bobPrivateKey = buffer;
                string result = Encoding.UTF8.GetString(iv);
                using (Stream file = File.OpenWrite(output))
                {
                    file.Write(encryptedMessage, 0, encryptedMessage.Length);
                }
            }

            File.Delete(input);

            String[] keys_set1 = new String[10];
            for (i = 0; i < 10; i++)
            {

                keys_set1[i] = Common.AlphanumericString();
            }

        

            string connection_string = Database.cs;
            //string connection_string1 = Database.cs1;
            //string connection_string2 = Database.cs2;

            SqlCommand cmd = new SqlCommand("Upload_Data_on_Cloud");
            var sqltype = CommandType.StoredProcedure;
            SqlParameter[] sqlpara = {
                                     new SqlParameter("@file_name",file_path),
                                     new SqlParameter("@file_path",file_name1),
                                     new SqlParameter("@key_value",encryptedkey),
                                     new SqlParameter("@FileKey",bobPrivateKey),
                                     new SqlParameter("@IV",iv),
                                 };
            Database.Insertdata(connection_string, cmd, sqlpara, sqltype);

            string query = "Insert Into File_Info values('" + file_path + "','" + encryptedkey + "','" + file_name1 + "','" + file_name2 + "','" + file_name3 + "')";
            Database.InsertData_direct(query);
            Response.Redirect("Manage Files.aspx?msg=add");

        }

    }
    private void Encrypt(string key, string inputFilePath, string outputfilePath)
    {
        string EncryptionKey = key;
        using (Aes encryptor = Aes.Create())
        {
            Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 });
            encryptor.Key = pdb.GetBytes(32);
            encryptor.IV = pdb.GetBytes(16);
            using (FileStream fsOutput = new FileStream(outputfilePath, FileMode.Create))
            {
                using (CryptoStream cs = new CryptoStream(fsOutput, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    using (FileStream fsInput = new FileStream(inputFilePath, FileMode.Open))
                    {
                        int data;
                        while ((data = fsInput.ReadByte()) != -1)
                        {
                            cs.WriteByte((byte)data);
                        }
                    }
                }
            }
        }
    }

}
