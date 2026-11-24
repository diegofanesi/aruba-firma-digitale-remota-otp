from .cli import main

if __name__ == "__main__":  # the guard matters: verification runs in a spawned process that re-imports __main__
    raise SystemExit(main())
