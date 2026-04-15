using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Cryptography.Models
{
    public class ClassicalCipherViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập bản rõ/bản mã.")]
        [Display(Name = "Nội dung")]
        public string InputText { get; set; } = string.Empty;

        [Display(Name = "Kết quả")]
        public string OutputText { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Loại mật mã")]
        public string CipherType { get; set; } = "caesar";

        [Required]
        [Display(Name = "Chế độ")]
        public string Mode { get; set; } = "encrypt";

        [Range(1, 25, ErrorMessage = "Shift phải trong khoảng 1 đến 25.")]
        [Display(Name = "Shift (Caesar)")]
        public int Shift { get; set; } = 3;

        [Display(Name = "Khóa (Vigenere)")]
        public string VigenereKey { get; set; } = "LEMON";

        public List<CipherOption> AvailableCiphers { get; set; } =
        [
            new CipherOption { Value = "caesar", Label = "Mật mã Caesar" },
            new CipherOption { Value = "vigenere", Label = "Mật mã Vigenere" },
            new CipherOption { Value = "atbash", Label = "Mật mã Atbash" }
        ];

        public bool HasResult => !string.IsNullOrWhiteSpace(OutputText);
    }

    public class CipherOption
    {
        public string Value { get; set; } = string.Empty;

        public string Label { get; set; } = string.Empty;
    }
}
