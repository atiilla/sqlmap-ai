import os
from colorama import init, Fore, Style
init()
def print_banner():
    from sqlmap_ai.startup import show_startup_animation
    show_startup_animation()
def print_info(message, **kwargs):
    if 'end' in kwargs:
        print(f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}", end=kwargs['end'], flush=kwargs.get('flush', False))
    else:
        print(f"{Fore.BLUE}[INFO] {message}{Style.RESET_ALL}")
def print_success(message, **kwargs):
    if 'end' in kwargs:
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}", end=kwargs['end'], flush=kwargs.get('flush', False))
    else:
        print(f"{Fore.GREEN}[SUCCESS] {message}{Style.RESET_ALL}")
def print_warning(message, **kwargs):
    if 'end' in kwargs:
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}", end=kwargs['end'], flush=kwargs.get('flush', False))
    else:
        print(f"{Fore.YELLOW}[WARNING] {message}{Style.RESET_ALL}")
def print_error(message, **kwargs):
    if 'end' in kwargs:
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}", end=kwargs['end'], flush=kwargs.get('flush', False))
    else:
        print(f"{Fore.RED}[ERROR] {message}{Style.RESET_ALL}")
def get_target_url():
    print(f"\n{Fore.BLUE}URL format: http://example.com/page.php?id=1{Style.RESET_ALL}")
    print(f"{Fore.BLUE}For best results, include at least one parameter (e.g., ?id=1){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Do not use placeholder text like [TARGET_URL] - use a real URL{Style.RESET_ALL}")
    while True:
        url = input(f"{Fore.GREEN}Enter target URL: {Style.RESET_ALL}")
        if not url:
            print_warning("URL cannot be empty. Please enter a valid URL.")
            continue
        if not (url.startswith('http://') or url.startswith('https://')):
            print_warning("URL must start with http:// or https://")
            continue
        placeholders = ['[TARGET_URL]', '{target}', '<target>', 'example.com']
        if any(ph in url for ph in placeholders):
            print_warning(f"URL contains placeholder text ({', '.join(placeholders)}). Please use a real URL.")
            continue
        return url
def get_timeout():
    try:
        user_timeout = int(input(f"{Fore.GREEN}Enter timeout in seconds (default: 120): {Style.RESET_ALL}") or "120")
        return user_timeout
    except ValueError:
        print_warning("Invalid timeout value. Using default of 120 seconds.")
        return 120
def get_interactive_mode():
    return input(f"{Fore.GREEN}Run in interactive mode? (y/n, default: n): {Style.RESET_ALL}").lower() == 'y'
def get_user_choice(suggestions):
    suggested_cmd = ' '.join(suggestions)
    print(f"\n{Fore.CYAN}[AI SUGGESTION] {suggested_cmd}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}Choose your next action:{Style.RESET_ALL}")
    print(f"1. Use AI suggestion: {suggested_cmd}")
    print("2. Enter custom SQLMap options")
    print("3. Skip further testing")
    while True:
        choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}")
        if choice == '1':
            return suggestions
        elif choice == '2':
            custom_options = input(f"{Fore.GREEN}Enter custom SQLMap options: {Style.RESET_ALL}")
            return custom_options.split()
        elif choice == '3':
            return None
        else:
            print_warning("Invalid choice. Please enter 1, 2, or 3.")
def handle_timeout_ui(fallback_opts, target_url):
    print_warning("The scan timed out. This could be due to several reasons:")
    print("1. The target application might be slow to respond")
    print("2. Network latency issues")
    print("3. Intrusion prevention systems or WAFs might be blocking the scan")
    print("4. The target might be performing complex operations that take longer")
    print_info("\nRecommended actions:")
    print("1. Continue with the partial data we've collected")
    print("2. Try again with more targeted techniques (--technique=B or --technique=T)")
    print("3. Increase the scan timeout")
    print(f"\n{Fore.CYAN}[RECOMMENDATION] Try: sqlmap -u {target_url} {' '.join(fallback_opts)}{Style.RESET_ALL}")
    choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}")
    if choice == '2':
        reduced_timeout = int(input(f"{Fore.GREEN}Enter new timeout in seconds (default: 180): {Style.RESET_ALL}") or "180")
        return choice, reduced_timeout
    elif choice == '3':
        new_timeout = int(input(f"{Fore.GREEN}Enter new timeout in seconds (default: 300): {Style.RESET_ALL}") or "300")
        return choice, new_timeout
    else:
        return '1', None
def handle_no_data_timeout_ui(target_url):
    print("1. Try again with a simpler, faster scan (--tech=BT --level=1)")
    print("2. Try increasing the timeout value")
    print("3. Try with a different URL or parameter")
    fallback_opts = ["--tech=BT", "--level=1", "--risk=1"]
    print(f"\n{Fore.CYAN}[RECOMMENDATION] Try: sqlmap -u {target_url} {' '.join(fallback_opts)}{Style.RESET_ALL}")
    choice = input(f"\n{Fore.GREEN}Enter your choice (1-3): {Style.RESET_ALL}")
    if choice == '1':
        reduced_timeout = int(input(f"{Fore.GREEN}Enter new timeout in seconds (default: 120): {Style.RESET_ALL}") or "120")
        return choice, reduced_timeout, fallback_opts
    elif choice == '2':
        new_timeout = int(input(f"{Fore.GREEN}Enter new timeout in seconds (default: 240): {Style.RESET_ALL}") or "240")
        return choice, new_timeout, None
    else:
        return '3', None, None
def confirm_save_report():
    return input(f"\n{Fore.GREEN}Save detailed report to file? (y/n): {Style.RESET_ALL}").lower() == 'y' 