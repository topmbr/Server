using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
namespace ConsoleApp110
{
    class Program
    {
        static Dictionary<string, string> connectedClients = new Dictionary<string, string>();
        class User
        {
            public string Username { get; set; }
            public TcpClient TcpClient { get; set; }
            public NetworkStream NetworkStream { get; set; }
            public DateTime ConnectionTime { get; set; }
            public string Password { get; internal set; }
        }

        static void Main()
        {
            TcpListener server = new TcpListener(IPAddress.Any, 8888);
            server.Start();
            Console.WriteLine("Server started...");
            connectedClients.Add("username1", "password1");
            connectedClients.Add("username2", "password2");
            while (true)
            {
                TcpClient client = server.AcceptTcpClient();
                Thread clientThread = new Thread(new ParameterizedThreadStart(HandleClient));
                clientThread.Start(client);
            }

        }
        static string ProcessRegistrationLogin(User user, string message)
        {
            string[] parts = message.Split('|');
            if (parts.Length < 3)
                return "FAILURE|Invalid format for registration/login.";

            string action = parts[0].ToUpper();
            string username = parts[1];
            string password = parts[2];

            if (action == "REGISTER")
            {
                if (connectedClients.ContainsKey(username))
                    return "FAILURE|Username already exists.";

                user.Username = username;
                user.Password = password;
                return "SUCCESS|Registration successful.";
            }
            else if (action == "LOGIN")
            {
                if (user.Password == password)
                    return "SUCCESS|Login successful.";
                else
                    return "FAILURE|Invalid username or password.";
            }
            else
            {
                return "FAILURE|Invalid action.";
            }
        }
        static void HandleClient(object obj)
        {
            TcpClient tcpClient = (TcpClient)obj;
            NetworkStream clientStream = tcpClient.GetStream();
            User user = AuthenticateClient(tcpClient, clientStream);

            if (user != null)
            {
                connectedClients.Add(user.Username, user.Password);
                Console.WriteLine($"{user.Username} connected.");

                while (true)
                {
                    string message = ReceiveMessage(user);
                    if (message == null)
                        break;

                    // Process and handle messages as needed
                    if (message.StartsWith("REGISTERLOGIN"))
                    {
                        string response = ProcessRegistrationLogin(user, message.Substring("REGISTERLOGIN|".Length));
                        SendMessage(user.NetworkStream, response);
                    }
                    else
                    {
                        Console.WriteLine($"{user.Username}: {message}");
                    }
                }

                Console.WriteLine($"{user.Username} disconnected.");
                connectedClients.Remove(user.Username);
            }
        }
        private static void HandleAuthentication(User user, string[] credentials)
        {
            string command = credentials[0];
            string enteredUsername = credentials[1];
            string enteredPassword = credentials[2];

            switch (command)
            {
                case "AUTH":
                    // Аутентификация или регистрация пользователя
                    AuthenticateOrRegister(user, enteredUsername, enteredPassword);
                    break;
                    // Другие обработки команд...
            }
        }

        private static void AuthenticateOrRegister(User user, string enteredUsername, string enteredPassword)
        {
            // Проверяем существует ли пользователь с таким логином
            if (connectedClients.ContainsKey(enteredUsername))
            {
                // Пользователь существует, проверяем пароль
                if (connectedClients[enteredUsername] == enteredPassword)
                {
                    // Пользователь успешно аутентифицирован
                    SendMessage(user.NetworkStream, "Authentication successful.");
                }
                else
                {
                    // Неверный пароль
                    SendMessage(user.NetworkStream, "Invalid password.");
                }
            }
            else
            {
                // Регистрируем нового пользователя
                connectedClients.Add(enteredUsername, enteredPassword);
                SendMessage(user.NetworkStream, "Registration successful.");
            }
        }
        static User AuthenticateClient(TcpClient tcpClient, NetworkStream clientStream)
        {
            // Implement user authentication logic here
            // For simplicity, let's assume the client sends username as the first message
            byte[] usernameBuffer = new byte[1024];
            int bytesRead = clientStream.Read(usernameBuffer, 0, usernameBuffer.Length);
            string username = Encoding.UTF8.GetString(usernameBuffer, 0, bytesRead).Trim();

            if (string.IsNullOrEmpty(username) || connectedClients.ContainsKey(username))
            {
                Console.WriteLine("Authentication failed.");
                return null;
            }

            User newUser = new User
            {
                Username = username,
                TcpClient = tcpClient,
                NetworkStream = clientStream,
                ConnectionTime = DateTime.Now
            };

            SendMessage(clientStream, "Authentication successful.");
            return newUser;
        }

        static string ReceiveMessage(User user)
        {
            // Implement message receiving logic here
            byte[] messageBuffer = new byte[1024];
            int bytesRead = user.NetworkStream.Read(messageBuffer, 0, messageBuffer.Length);

            if (bytesRead == 0)
                return null;

            return Encoding.UTF8.GetString(messageBuffer, 0, bytesRead).Trim();
        }

        static void SendMessage(NetworkStream clientStream, string message)
        {
            // Implement message sending logic here
            byte[] messageBytes = Encoding.UTF8.GetBytes(message);
            clientStream.Write(messageBytes, 0, messageBytes.Length);
        }

    }
}
