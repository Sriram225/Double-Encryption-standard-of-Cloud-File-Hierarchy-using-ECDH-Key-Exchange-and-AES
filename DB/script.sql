USE [master]
GO
/****** Object:  Database [ECC_FINAL]    Script Date: 08/05/2019 14:20:18 ******/
CREATE DATABASE [ECC_FINAL] ON  PRIMARY 
( NAME = N'ECC_FINAL', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\ECC_FINAL.mdf' , SIZE = 2048KB , MAXSIZE = UNLIMITED, FILEGROWTH = 1024KB )
 LOG ON 
( NAME = N'ECC_FINAL_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL10_50.MSSQLSERVER\MSSQL\DATA\ECC_FINAL_log.ldf' , SIZE = 1024KB , MAXSIZE = 2048GB , FILEGROWTH = 10%)
GO
ALTER DATABASE [ECC_FINAL] SET COMPATIBILITY_LEVEL = 100
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [ECC_FINAL].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [ECC_FINAL] SET ANSI_NULL_DEFAULT OFF
GO
ALTER DATABASE [ECC_FINAL] SET ANSI_NULLS OFF
GO
ALTER DATABASE [ECC_FINAL] SET ANSI_PADDING OFF
GO
ALTER DATABASE [ECC_FINAL] SET ANSI_WARNINGS OFF
GO
ALTER DATABASE [ECC_FINAL] SET ARITHABORT OFF
GO
ALTER DATABASE [ECC_FINAL] SET AUTO_CLOSE OFF
GO
ALTER DATABASE [ECC_FINAL] SET AUTO_CREATE_STATISTICS ON
GO
ALTER DATABASE [ECC_FINAL] SET AUTO_SHRINK OFF
GO
ALTER DATABASE [ECC_FINAL] SET AUTO_UPDATE_STATISTICS ON
GO
ALTER DATABASE [ECC_FINAL] SET CURSOR_CLOSE_ON_COMMIT OFF
GO
ALTER DATABASE [ECC_FINAL] SET CURSOR_DEFAULT  GLOBAL
GO
ALTER DATABASE [ECC_FINAL] SET CONCAT_NULL_YIELDS_NULL OFF
GO
ALTER DATABASE [ECC_FINAL] SET NUMERIC_ROUNDABORT OFF
GO
ALTER DATABASE [ECC_FINAL] SET QUOTED_IDENTIFIER OFF
GO
ALTER DATABASE [ECC_FINAL] SET RECURSIVE_TRIGGERS OFF
GO
ALTER DATABASE [ECC_FINAL] SET  DISABLE_BROKER
GO
ALTER DATABASE [ECC_FINAL] SET AUTO_UPDATE_STATISTICS_ASYNC OFF
GO
ALTER DATABASE [ECC_FINAL] SET DATE_CORRELATION_OPTIMIZATION OFF
GO
ALTER DATABASE [ECC_FINAL] SET TRUSTWORTHY OFF
GO
ALTER DATABASE [ECC_FINAL] SET ALLOW_SNAPSHOT_ISOLATION OFF
GO
ALTER DATABASE [ECC_FINAL] SET PARAMETERIZATION SIMPLE
GO
ALTER DATABASE [ECC_FINAL] SET READ_COMMITTED_SNAPSHOT OFF
GO
ALTER DATABASE [ECC_FINAL] SET HONOR_BROKER_PRIORITY OFF
GO
ALTER DATABASE [ECC_FINAL] SET  READ_WRITE
GO
ALTER DATABASE [ECC_FINAL] SET RECOVERY FULL
GO
ALTER DATABASE [ECC_FINAL] SET  MULTI_USER
GO
ALTER DATABASE [ECC_FINAL] SET PAGE_VERIFY CHECKSUM
GO
ALTER DATABASE [ECC_FINAL] SET DB_CHAINING OFF
GO
EXEC sys.sp_db_vardecimal_storage_format N'ECC_FINAL', N'ON'
GO
USE [ECC_FINAL]
GO
/****** Object:  Table [dbo].[FileLog]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FileLog](
	[logId] [int] IDENTITY(1,1) NOT NULL,
	[User_id] [int] NULL,
	[share_id] [int] NULL,
	[LogType] [int] NULL,
	[LogDate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[File_Master]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[File_Master](
	[file_id] [int] IDENTITY(1,1) NOT NULL,
	[file_path] [nvarchar](max) NULL,
	[key_value] [nvarchar](50) NULL,
	[file_name] [nvarchar](max) NULL,
	[FileKey] [image] NULL,
	[IV] [image] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[File_Master] ON
INSERT [dbo].[File_Master] ([file_id], [file_path], [key_value], [file_name], [FileKey], [IV]) VALUES (1, N'Jellyfish_enc1.jpg', N'7Xv4k2Oai7td58vc', N'Jellyfish.jpg', 0x3B7FBEDDF2BF72EDC0E16605171D629AD58F02D73F189D61AE100C9627F795F2, 0x12020EACD91590E7E9AA2C6A86A297E6)
INSERT [dbo].[File_Master] ([file_id], [file_path], [key_value], [file_name], [FileKey], [IV]) VALUES (2, N'Koala_enc1.jpg', N'KhHS9Ddsu2E8xsRl', N'Koala.jpg', 0xB5D5F93164BDB83AD4F0FC9C1E83376E6E73D141FB859ABB24BAA2EC65A37496, 0x49013FFB2E9F64DA011B40A312177F70)
INSERT [dbo].[File_Master] ([file_id], [file_path], [key_value], [file_name], [FileKey], [IV]) VALUES (3, N'H1_enc1.txt', N'abc456dxfdgy5754rtgdfr', N'H1.txt', 0x18BE5FEB0EA8AB1AF6AF4D34BC0C8F138185077742052AEBADBDA7931E0F6D61, 0x01FBEC87FCBC0E1278266AFE0F01946E)
INSERT [dbo].[File_Master] ([file_id], [file_path], [key_value], [file_name], [FileKey], [IV]) VALUES (4, N'Aroma_enc1.png', N'CRRKVzCcdOUYgg4G', N'Aroma.png', 0x6B565C35BB858709B6F8DC5603D214BB619890220A25C158DD6E8008C2B68C74, 0xCFE854A93DE57BED6AC7D6FCFE1E4B11)
SET IDENTITY_INSERT [dbo].[File_Master] OFF
/****** Object:  Table [dbo].[File_Info]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[File_Info](
	[file_id] [int] IDENTITY(1,1) NOT NULL,
	[file_name] [nvarchar](50) NULL,
	[key1] [nvarchar](50) NULL,
	[cloud1_file_path] [nvarchar](max) NULL,
	[cloud2_file_path] [nvarchar](max) NULL,
	[cloud3_file_path] [nvarchar](max) NULL
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[File_Info] ON
INSERT [dbo].[File_Info] ([file_id], [file_name], [key1], [cloud1_file_path], [cloud2_file_path], [cloud3_file_path]) VALUES (1, N'Jellyfish.jpg', N'7Xv4k2Oai7td58vc', N'Jellyfish_enc1.jpg', N'Jellyfish_enc2.jpg', N'Jellyfish_enc3.jpg')
INSERT [dbo].[File_Info] ([file_id], [file_name], [key1], [cloud1_file_path], [cloud2_file_path], [cloud3_file_path]) VALUES (2, N'Koala.jpg', N'KhHS9Ddsu2E8xsRl', N'Koala_enc1.jpg', N'Koala_enc2.jpg', N'Koala_enc3.jpg')
INSERT [dbo].[File_Info] ([file_id], [file_name], [key1], [cloud1_file_path], [cloud2_file_path], [cloud3_file_path]) VALUES (3, N'H1.txt', N'abc456dxfdgy5754rtgdfr', N'H1_enc1.txt', N'H1_enc2.txt', N'H1_enc3.txt')
INSERT [dbo].[File_Info] ([file_id], [file_name], [key1], [cloud1_file_path], [cloud2_file_path], [cloud3_file_path]) VALUES (4, N'Aroma.png', N'CRRKVzCcdOUYgg4G', N'Aroma_enc1.png', N'Aroma_enc2.png', N'Aroma_enc3.png')
SET IDENTITY_INSERT [dbo].[File_Info] OFF
/****** Object:  Table [dbo].[auto_keys]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[auto_keys](
	[key_id] [int] IDENTITY(1,1) NOT NULL,
	[key_value] [nvarchar](50) NULL
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[auto_keys] ON
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (1, N'HhOF5M4iSBDqH9t5')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (2, N'RSsXECK53QMENjwx')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (3, N'KezM2QyHrzSykUG8')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (4, N'NZoDpCFtMvp4zh7c')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (5, N'hTAN4Pd4pLdbpWek')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (6, N'I4y8UvLFTbXxvnwz')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (7, N'n7B1DuiIN0m6ZxIH')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (8, N'WP3A9IVt9SR0uKtX')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (9, N'D6dwG5b5QfLsCpTL')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (10, N'49piNgLbCag98txg')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (11, N'hmwhoNoffvOWNqqP')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (12, N'p6nYt32NVTLSAcy5')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (13, N'SONnbF9VhOTQeMkG')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (14, N'jrsqOV5Fr5ac0Bks')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (15, N'ZCMXpvaRk7tcNftr')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (16, N'QHIF1Jy8x0Dx33ND')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (17, N'eSkgUf7TGHnewoGP')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (18, N'ototObNbfEhlyMJM')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (19, N'zGr7z0f5AjRiSyYZ')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (20, N'TqAj0QA5YG9MQ6Tv')
INSERT [dbo].[auto_keys] ([key_id], [key_value]) VALUES (21, N'abc456dxfdgy5754rtgdfr')
SET IDENTITY_INSERT [dbo].[auto_keys] OFF
/****** Object:  Table [dbo].[admin_login]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[admin_login](
	[admin_id] [int] IDENTITY(1,1) NOT NULL,
	[username] [nvarchar](50) NULL,
	[password] [nvarchar](50) NULL
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[admin_login] ON
INSERT [dbo].[admin_login] ([admin_id], [username], [password]) VALUES (1, N'admin', N'admin')
SET IDENTITY_INSERT [dbo].[admin_login] OFF
/****** Object:  Table [dbo].[Share_Master]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Share_Master](
	[share_id] [int] IDENTITY(1,1) NOT NULL,
	[file_name] [nvarchar](50) NULL,
	[username] [nvarchar](50) NULL,
	[cloud_id] [nvarchar](50) NULL,
	[fid] [int] NULL
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[Share_Master] ON
INSERT [dbo].[Share_Master] ([share_id], [file_name], [username], [cloud_id], [fid]) VALUES (1, N'Jellyfish.jpg', N'swapnilgurav94@gmail.com', N'Cloud', 1)
INSERT [dbo].[Share_Master] ([share_id], [file_name], [username], [cloud_id], [fid]) VALUES (2, N'Koala.jpg', N'test1@gmail.com', N'Cloud', 2)
INSERT [dbo].[Share_Master] ([share_id], [file_name], [username], [cloud_id], [fid]) VALUES (3, N'H1.txt', N'swapnilgurav94@gmail.com', N'Cloud', 3)
INSERT [dbo].[Share_Master] ([share_id], [file_name], [username], [cloud_id], [fid]) VALUES (4, N'Aroma.png', N'swapnilgurav94@gmail.com', N'Cloud', 4)
SET IDENTITY_INSERT [dbo].[Share_Master] OFF
/****** Object:  Table [dbo].[User_Master]    Script Date: 08/05/2019 14:20:19 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[User_Master](
	[user_id] [int] IDENTITY(1,1) NOT NULL,
	[full_name] [nvarchar](50) NULL,
	[contact_no] [nvarchar](50) NULL,
	[email_id] [nvarchar](50) NULL,
	[address] [nvarchar](max) NULL,
	[password] [nvarchar](50) NULL
) ON [PRIMARY]
GO
SET IDENTITY_INSERT [dbo].[User_Master] ON
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (1, N'Nivruti B Kore', N'9632587410', N'nivrutikore@gmail.com', N'Ghansoli , New Mumbai', N'12345')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (3, N'chintan', N'9892369017', N'guidance@projectideas.co.in', N'Kandivali-west', N'9A0v0eim')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (4, N'maher', N'9892369017', N'tejas18mohite@gmail.com', N'Kandivali-west', N'PUi5lZbI')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (5, N'ankit', N'8605973598', N'ankitkesarwani122@gmail.com', N'kandivali', N'5GOPXvkW')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (6, N'swapnil', N'9892369017', N'swapnilgurav94@gmail.com', N'Kandivali west', N'123456')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (7, N'test1', N'9874561230', N'test1@gmail.com', N'mumbai', N'qUYaJ9wP')
INSERT [dbo].[User_Master] ([user_id], [full_name], [contact_no], [email_id], [address], [password]) VALUES (8, N'test', N'9892369017', N'test@gmail.com', N'Kandivali west', N'y86hPcR6')
SET IDENTITY_INSERT [dbo].[User_Master] OFF
/****** Object:  StoredProcedure [dbo].[Upload_Data_on_Cloud]    Script Date: 08/05/2019 14:20:20 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[Upload_Data_on_Cloud]
	@file_path nvarchar(200),
	@key_value nvarchar(50),
	@file_name nvarchar(200),
	@FileKey image,
	@IV image
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    Insert Into File_Master values(@file_path,@key_value, @file_name,@FileKey,@IV)
END
GO
/****** Object:  StoredProcedure [dbo].[Select_info]    Script Date: 08/05/2019 14:20:20 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[Select_info]
	@file_name nvarchar(200)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	SELECT * from File_Master where file_name=@file_name
END
GO
/****** Object:  StoredProcedure [dbo].[Select_Data]    Script Date: 08/05/2019 14:20:20 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[Select_Data]
	@file_name nvarchar(200)
AS
BEGIN
	-- SET NOCOUNT ON added to prevent extra result sets from
	-- interfering with SELECT statements.
	SET NOCOUNT ON;

    -- Insert statements for procedure here
	select * from File_Master where file_name=@file_name
END
GO
/****** Object:  StoredProcedure [dbo].[CompareKeys]    Script Date: 08/05/2019 14:20:20 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[CompareKeys]
	@key_value varchar(500)
As
BEGIN
	SET NOCOUNT ON;
	Declare @count int;
	set @count = 0;
	-- Check key id 
	
	Declare @keyValue varchar(500);
	--select @keyValue = key_id from ECC_algorithm.dbo.auto_keys where key_value = @key_value
	Select @keyValue=key_value from File_Master where key_value = @key_value
	if(@keyValue is not null)
	begin		
		begin
			select file_id, file_path,file_name from File_Master where key_value = @keyValue
		end
		
		
 	End
 	else 
 	begin
 		-- key value is wrong
 		
 		return 0;
 	end 
 	
 	 
 	
END
GO
