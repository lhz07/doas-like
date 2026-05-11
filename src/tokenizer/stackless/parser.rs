use crate::tokenizer::stackless::Val;
use crate::tokenizer::{QuoteState, State, Token};

pub async fn tokenizer(co: &Val<State>, content: &str) {
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
                    co.yield_(State::Token(
                        token.finish(quote_state.take_option()),
                        line_count,
                    ))
                    .await;
                }
                if !token_empty {
                    token_empty = true;
                    co.yield_(State::NewLine(line_count)).await;
                }
                line_count += 1;
            }
            _ if ch.is_ascii_whitespace() => {
                if !token.str.is_empty() {
                    token_empty = false;
                    co.yield_(State::Token(
                        token.finish(quote_state.take_option()),
                        line_count,
                    ))
                    .await;
                }
                continue;
            }
            '{' | '}' => {
                if !token.str.is_empty() {
                    token_empty = false;
                    co.yield_(State::Token(
                        token.finish(quote_state.take_option()),
                        line_count,
                    ))
                    .await;
                }
                token.str.push(ch);
                co.yield_(State::Token(
                    token.finish(quote_state.take_option()),
                    line_count,
                ))
                .await;
                continue;
            }
            // skip comment
            '#' => {
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
    if !token.str.is_empty() {
        token_empty = false;
        co.yield_(State::Token(
            token.finish(quote_state.take_option()),
            line_count,
        ))
        .await;
    }
    if !token_empty {
        co.yield_(State::NewLine(line_count)).await;
    }
}

#[test]
fn test_tokenizer() {
    use crate::gen_iter;
    let content = include_str!("../../../tests/test0.conf");
    gen_iter!(iter, |co| tokenizer(co, content));
    for token in iter {
        println!("{:?}", token);
    }
}
