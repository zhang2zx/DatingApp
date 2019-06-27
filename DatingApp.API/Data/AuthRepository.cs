using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    public class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;
        public AuthRepository(DataContext context){

            _context = context;
        }
        

        public async Task<User> Register(User user, string password)
        { //translate the passward into Hash and salt then save it
           byte[] passwordHash, passwordSalt;
           CreatePasswordHash(password, out passwordHash, out passwordSalt);

           user.PasswordHash = passwordHash;
           user.PasswordSalt = passwordSalt;

           await _context.Users.AddAsync(user);
           await _context.SaveChangesAsync();

           return user;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        { //create hash passward process
            using(var hmac= new System.Security.Cryptography.HMACSHA512()){

                passwordSalt=hmac.Key;
                //salt is random
                passwordHash=hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                //hash is created by the password
            }
        }
        public async Task<User> Login(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x=> x.Username==username);
            if(user == null)
                return null;
            if(!VarifyPasswordHash(password,user.PasswordHash,user.PasswordSalt))
                return null;
            
            return user;
        }


        //check the input of passward, compare it with the stored password
        private bool VarifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac= new System.Security.Cryptography.HMACSHA512(passwordSalt)){

                var computeHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)); 
                for(int i=0; i<computeHash.Length; i++){
                    if(computeHash[i] != passwordHash[i])
                    return false;
                }
            }
            return true;
        }
        public async Task<bool> UserExit(string username)
        {
            if(await _context.Users.AnyAsync(x=> x.Username == username))
            return true;

            return false;
        }
    }
}