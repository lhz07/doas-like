use crate::tokenizer::{QuoteState, State, Token, Tokenizer};

gen fn tokenizer(content: &str) -> State {
    let mut token = Token::default();
    let mut quote_state = QuoteState::default();
    let mut skipping_comment = false;
    let mut token_empty = true;
    let mut line_count = 1;
    let mut escaped = false;
    let mut quoted = false;
    for ch in content.chars() {
        if skipping_comment {
            if ch != '\n' {
                continue;
            } else {
                // ch == '\n'
                skipping_comment = false;
            }
        }
        if escaped {
            match ch {
                '\n' => line_count += 1,
                _ => token.str.push(ch),
            }
            escaped = false;
            continue;
        }
        if quoted {
            match ch {
                '"' | '\\' => (),
                _ => {
                    token.str.push(ch);
                    continue;
                }
            }
        }
        match ch {
            '\n' => {
                if !token.str.is_empty() {
                    token_empty = false;
                    yield State::Token(token.finish(quote_state.take_option()), line_count);
                }
                if !token_empty {
                    token_empty = true;
                    yield State::NewLine(line_count);
                }
                line_count += 1;
            }
            _ if ch.is_ascii_whitespace() => {
                if !token.str.is_empty() {
                    token_empty = false;
                    yield State::Token(token.finish(quote_state.take_option()), line_count);
                }
                continue;
            }
            '{' | '}' => {
                if !token.str.is_empty() {
                    token_empty = false;
                    yield State::Token(token.finish(quote_state.take_option()), line_count);
                }
                token.str.push(ch);
                yield State::Token(token.finish(quote_state.take_option()), line_count);
                continue;
            }
            // skip comment
            '#' => {
                if !token.str.is_empty() {
                    token_empty = false;
                    yield State::Token(token.finish(quote_state.take_option()), line_count);
                }
                if !token_empty {
                    token_empty = true;
                    yield State::NewLine(line_count);
                }
                skipping_comment = true;
            }
            '\\' => {
                escaped = !escaped;
                continue;
            }
            '"' => {
                quoted = !quoted;
                match &quote_state {
                    QuoteState::None if quoted => quote_state = QuoteState::Half(token.str.len()),
                    QuoteState::Half(start) if !quoted && token.str.len() > *start => {
                        quote_state = QuoteState::Full(*start..token.str.len())
                    }
                    _ => (),
                }
                continue;
            }
            _ => {
                token.str.push(ch);
            }
        }
    }
}

pub fn gen_tokenizer(content: &str) -> Tokenizer<impl Iterator<Item = State>> {
    let g = tokenizer(content);
    Tokenizer {
        tokenizer: g.peekable(),
        line: 1,
    }
}

#[test]
fn test_tokenizer() {
    let content = std::fs::read_to_string("tests/test0.conf").unwrap();
    let iter = tokenizer(&content);
    for token in iter {
        println!("{:?}", token);
    }
}
