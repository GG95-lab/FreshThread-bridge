// Ported from the existing objective-command allowlist; never executes a command.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectiveVerifierKind {
    Build,
    Test,
}

pub fn classify_builtin(command: &str) -> Option<ObjectiveVerifierKind> {
    if command
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | b';' | b'&' | b'|' | b'<' | b'>'))
    {
        return None;
    }
    let tokens = command.split_ascii_whitespace().collect::<Vec<_>>();
    let (program, arguments) = tokens.split_first()?;
    let program = program
        .strip_suffix(".exe")
        .or_else(|| program.strip_suffix(".cmd"))
        .unwrap_or(program)
        .to_ascii_lowercase();
    let javascript = matches!(program.as_str(), "pnpm" | "npm" | "yarn" | "bun");
    let arguments = if javascript {
        package_manager_command(arguments)?
    } else {
        arguments
    };
    let first = arguments.first().copied();
    let second = arguments.get(1).copied();
    let test = (program == "cargo" && matches!(first, Some("test" | "nextest")))
        || (javascript
            && (first == Some("test") || (first == Some("run") && second == Some("test"))))
        || (matches!(program.as_str(), "go" | "dotnet") && first == Some("test"))
        || program == "pytest"
        || (matches!(program.as_str(), "python" | "python3")
            && first == Some("-m")
            && second == Some("pytest"));
    if test {
        return Some(ObjectiveVerifierKind::Test);
    }
    let build = (program == "cargo" && matches!(first, Some("build" | "check" | "clippy")))
        || (javascript
            && (first == Some("build")
                || first == Some("check")
                || first == Some("typecheck")
                || (first == Some("run") && second == Some("build"))
                || (first == Some("run") && matches!(second, Some("check" | "typecheck")))
                || (first == Some("tauri") && second == Some("build"))))
        || (matches!(program.as_str(), "go" | "dotnet") && first == Some("build"));
    build.then_some(ObjectiveVerifierKind::Build)
}

fn package_manager_command<'a>(mut arguments: &'a [&'a str]) -> Option<&'a [&'a str]> {
    while let Some((first, remaining)) = arguments.split_first() {
        if matches!(*first, "--dir" | "--cwd" | "--prefix" | "-C") {
            let (_, after_value) = remaining.split_first()?;
            arguments = after_value;
            continue;
        }
        if first.starts_with("--dir=")
            || first.starts_with("--cwd=")
            || first.starts_with("--prefix=")
        {
            arguments = remaining;
            continue;
        }
        break;
    }
    (!arguments.is_empty()).then_some(arguments)
}
