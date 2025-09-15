using System.ComponentModel.DataAnnotations;

namespace SchoolManagementSystem.Models.AccountViewModels
{
    public class ProfileViewModel
    {
        [Display(Name = "Username")]
        public string? Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email address")]
        [Display(Name = "Email")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "First name is required")]
        [Display(Name = "First Name")]
        [StringLength(50, ErrorMessage = "First name cannot be longer than 50 characters")]
        public string FirstName { get; set; } = string.Empty;

        [Required(ErrorMessage = "Last name is required")]
        [Display(Name = "Last Name")]
        [StringLength(50, ErrorMessage = "Last name cannot be longer than 50 characters")]
        public string LastName { get; set; } = string.Empty;

        [Phone(ErrorMessage = "Invalid phone number")]
        [Display(Name = "Phone Number")]
        [StringLength(20, ErrorMessage = "Phone number cannot be longer than 20 characters")]
        public string? PhoneNumber { get; set; } = string.Empty;

        [Display(Name = "Gender")]
        [StringLength(10, ErrorMessage = "Gender cannot be longer than 10 characters")]
        public string? Gender { get; set; } = string.Empty;

        [Display(Name = "Email Confirmed")]
        public bool IsEmailConfirmed { get; set; }
    }
}
