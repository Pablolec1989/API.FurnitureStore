﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace API.FurnitureStore.Shared.Common
{
    public class RandomGenerator
    {
        public static string GenerateRandomString(int size)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJLMNOPQRSTUVWXYZabcdefghijlmnopqrstuvwxyz$_-#";

            return new string(Enumerable.Repeat(chars, size).
                Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}
