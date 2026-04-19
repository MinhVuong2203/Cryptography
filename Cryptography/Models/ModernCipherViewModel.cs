using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Cryptography.Models
{
    public class ModernCipherViewModel
    {
        [Required(ErrorMessage = "Vui lòng nhập nội dung.")]
        [Display(Name = "Nội dung")]
        public string InputText { get; set; } = string.Empty;

        [Display(Name = "Kết quả")]
        public string OutputText { get; set; } = string.Empty;

        [Required]
        [Display(Name = "Loại mật mã")]
        public string CipherType { get; set; } = "tiny-a5-1";

        [Required]
        [Display(Name = "Chế độ")]
        public string Mode { get; set; } = "encrypt";

        [Required(ErrorMessage = "Vui lòng nhập khóa.")]
        [MinLength(4, ErrorMessage = "Khóa tối thiểu 4 ký tự.")]
        [Display(Name = "Khóa")]
        public string Key { get; set; } = string.Empty;

        public List<CipherOption> AvailableCiphers { get; set; } =
        [
            new CipherOption { Value = "tiny-a5-1", Label = "Tiny A5/1" },
            new CipherOption { Value = "tiny-rc4", Label = "Tiny RC4" },
            new CipherOption { Value = "a5-1", Label = "A5/1" },
            new CipherOption { Value = "rc4", Label = "RC4" }
        ];

        public bool HasResult => !string.IsNullOrWhiteSpace(OutputText);
    }
}