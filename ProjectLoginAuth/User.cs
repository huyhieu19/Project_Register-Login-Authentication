namespace ProjectLoginAuth
{
    public class User
    {
        public string UserName { get; set; } = string.Empty;
        public byte[] PasswordHash { get; set; }
        public byte[] PasswordSalt { get; set; }
        public string RefreshToken { get; set; } = string.Empty;

        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}
