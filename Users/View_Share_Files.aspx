<%@ Page Language="C#" AutoEventWireup="true" CodeFile="View_Share_Files.aspx.cs"
    Inherits="Users_View_Share_Files" %>

<%@ Register TagPrefix="uc1" TagName="header" Src="~/Users/Includes/Header.ascx" %>
<%@ Register TagPrefix="uc2" TagName="footer" Src="~/Users/Includes/Footer.ascx" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head id="Head1" runat="server">
    <title>Home</title>
    <meta name="description" content="" />
    <meta name="keywords" content="" />
    <meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
    <link href="css/style.css" rel="stylesheet" type="text/css" />
</head>
<body>
    <form id="form1" runat="server">
    <div class="page-out">
        <div class="page-in">
            <div class="page">
                <div class="main">
                    <uc1:header ID="header" runat="server" />
                    <div class="content">
                        <br />
                        <asp:GridView Width="100%" ID="GridView1" runat="server" AllowSorting="True"
                            AutoGenerateColumns="False" CellPadding="4" ForeColor="#333333" 
                            GridLines="None">
                            <AlternatingRowStyle BackColor="White" />
                            <Columns>
                                <asp:BoundField DataField="share_id" HeaderText="File Id" InsertVisible="False" ReadOnly="True"
                                    SortExpression="share_id">
                                <ItemStyle HorizontalAlign="Center" />
                                </asp:BoundField>
                                <asp:BoundField DataField="file_name" HeaderText="File Name" SortExpression="file_name">
                                <ItemStyle HorizontalAlign="Center" />
                                </asp:BoundField>
                                <asp:HyperLinkField DataNavigateUrlFields="share_id" 
                                    DataNavigateUrlFormatString="Download_File.aspx?action=download&amp;share_id={0}" 
                                    HeaderText="Action" Text="Download" >
                                <ItemStyle HorizontalAlign="Center" />
                                </asp:HyperLinkField>
                            </Columns>
                            <EditRowStyle BackColor="#2461BF" />
                            <FooterStyle BackColor="#507CD1" Font-Bold="True" ForeColor="White" />
                            <HeaderStyle BackColor="#507CD1" Font-Bold="True" ForeColor="White" />
                            <PagerStyle BackColor="#2461BF" ForeColor="White" HorizontalAlign="Center" />
                            <RowStyle BackColor="#EFF3FB" />
                            <SelectedRowStyle BackColor="#D1DDF1" Font-Bold="True" ForeColor="#333333" />
                            <SortedAscendingCellStyle BackColor="#F5F7FB" />
                            <SortedAscendingHeaderStyle BackColor="#6D95E1" />
                            <SortedDescendingCellStyle BackColor="#E9EBEF" />
                            <SortedDescendingHeaderStyle BackColor="#4870BE" />
                        </asp:GridView>
                    </div>
                    <uc2:footer ID="footer" runat="server" />
                </div>
            </div>
        </div>
    </div>
    </form>
</body>
</html>
