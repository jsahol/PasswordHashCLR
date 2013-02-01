using System;
using System.Data;
using System.Data.SqlClient;
using System.Data.SqlTypes;
using Microsoft.SqlServer.Server;
using System.Security.Cryptography;

public partial class UserDefinedFunctions
{
    [Microsoft.SqlServer.Server.SqlFunction]
    public static SqlString GenerateSalt(int length)
    {
        byte[] array = new byte[length];
        RNGCryptoServiceProvider rNGCryptoServiceProvider = new RNGCryptoServiceProvider();
        rNGCryptoServiceProvider.GetBytes(array);
        return new SqlString(Convert.ToBase64String(array));
    }

    [Microsoft.SqlServer.Server.SqlFunction]
    public static SqlString HashPassword(string password)
    {
        if (password == null) throw new ArgumentNullException("password");
        byte[] salt;
        byte[] bytes;
        Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(password, 16, 1000);

        salt = rfc2898DeriveBytes.Salt;
        bytes = rfc2898DeriveBytes.GetBytes(32);

        byte[] array = new byte[49];
        Buffer.BlockCopy(salt, 0, array, 1, 16);
        Buffer.BlockCopy(bytes, 0, array, 17, 32);

        return new SqlString(Convert.ToBase64String(array));
    }
};

