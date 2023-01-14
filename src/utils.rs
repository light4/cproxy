use std::process::Command;

pub fn command_to_string(cmd: &Command) -> String {
    let prog_env = cmd
        .get_envs()
        .map(|(k, v)| {
            if let Some(value) = v {
                format!("{}={}", k.to_string_lossy(), value.to_string_lossy())
            } else {
                format!("{}", k.to_string_lossy())
            }
        })
        .collect::<Vec<String>>()
        .join(" ");
    let prog_name = cmd.get_program().to_string_lossy();
    let prog_args = cmd
        .get_args()
        .map(|i| {
            let arg = i.to_string_lossy();
            if arg.chars().any(|it| it.is_ascii_whitespace()) {
                format!("\"{}\"", arg.escape_default())
            } else {
                arg.to_string()
            }
        })
        .collect::<Vec<String>>()
        .join(" ");

    let mut result = String::new();
    if !prog_env.is_empty() {
        result.push_str(&prog_env);
        result.push(' ');
    }
    result.push_str(&prog_name);
    result.push(' ');
    result.push_str(&prog_args);

    result
}
