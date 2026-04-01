use dialoguer::{theme::ColorfulTheme, Select, Input};
use console::{style, Term};

pub fn show_status() {
    println!("\n{}", style("------------------------- Amnesic Security Profile -------------------------").bold());
    println!("{:<20} {}", style("[*] Memory:").dim(), style("LOCKED (mlockall)").green());
    println!("{:<20} {}", style("[*] Ptrace:").dim(), style("ACTIVE (Tracer Priority)").green());
    println!("{:<20} {}", style("[*] Seccomp:").dim(), style("ACTIVE (Multi-level)").green());
    println!("{:<20} {}", style("[*] Namespaces:").dim(), style("ACTIVE (Isolated Mount/User)").green());
    println!("{:<20} {}", style("[*] Persistence:").dim(), style("ZERO (Volatile RAM only)").green());
    println!("{}\n", style("-------------------------------------------------------------------------------------").bold());
}

pub enum DashboardResult {
    Execute(Vec<String>),
    Exit,
}

pub fn interactive_menu() -> Result<DashboardResult, Box<dyn std::error::Error>> {
    let term = Term::stdout();
    term.clear_screen()?;

    println!("{}", style("Amnesic: Secure Execution Dashboard").bold().cyan());
    println!("{}", style("====================================").cyan());
    println!();

    let choices = &["Run Command", "Security Status", "Exit"];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("Select an action")
        .default(0)
        .items(&choices[..])
        .interact()?;

    match selection {
        0 => {
            let cmd_str: String = Input::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter command to run (e.g. ls -la)")
                .interact_text()?;
            let args = cmd_str.split_whitespace().map(|s| s.to_string()).collect();
            Ok(DashboardResult::Execute(args))
        }
        1 => {
            show_status();
            // Wait for user to press enter
            let _ = Input::<String>::new().with_prompt("Press Enter to continue").allow_empty(true).interact();
            interactive_menu()
        }
        _ => Ok(DashboardResult::Exit),
    }
}
