from __future__ import annotations
import sys
import click
from mocopos.llm.interpreter import LLMInterpreter

@click.command()
@click.option("--model", default=None, help="Override model (e.g. gpt-4o, gpt-4o-mini).")
def main(model: str | None):
    interp = LLMInterpreter(model=model) if model else LLMInterpreter()
    click.echo("Mocopos chat — type 'exit' to quit.\n")
    history = []
    while True:
        try:
            prompt = input("you> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not prompt or prompt.lower() in {"exit", "quit"}:
            break
        reply = interp.chat(prompt, history=history)
        print(f"\nassistant> {reply}\n")
        history.extend([{"role": "user", "content": prompt},
                        {"role": "assistant", "content": reply}])

if __name__ == "__main__":
    sys.exit(main())
