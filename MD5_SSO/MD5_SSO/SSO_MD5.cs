using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Security.Cryptography;

namespace SSO_MD5
{
    public class MD5
    {
        public string URL(string URLBase,string Secret,string Usuario,string Correo)
        {
            var tiempo = (DateTime.UtcNow.Subtract(new DateTime(1970,1,1))).TotalSeconds.ToString();
            return String.Format("{0}/login/sso?name={1}&email={2}&timestamp={3}&hash={4}",URLBase,Usuario,Correo,tiempo,Hash(Secret,Usuario,Correo,tiempo));
        }
        private string Hash(string Secret,string Usuario,string Correo,string tiempo)
        {
            var cadena = Usuario + Secret + Correo + tiempo;
            var keybytes = Encoding.UTF8.GetBytes(Secret);
            var inputBytes = Encoding.UTF8.GetBytes(cadena);
            var crypto = new HMACMD5(keybytes);
            var hash = crypto.ComputeHash(inputBytes);
            return hash.Select(b => b.ToString("x2")).Aggregate(new StringBuilder(),(current,next) => current.Append(next),current => current.ToString());
        }
    }
}
