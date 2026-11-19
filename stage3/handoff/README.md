# Stage 3 harness for the team

This folder is the version to use. It is on branch `stage3/mongoose-self-trial`.
`main` does not have these notes yet. Do not merge this branch into `main`
until the group asks for that.

The Mongoose pack on this branch is our example. You run the same harness
on your own Stage 2 target.

## Get the code

First time:

```sh
git clone git@github.com:ziqif-cmu-F25/AIOT.git
cd AIOT
git checkout stage3/mongoose-self-trial
```

You already have the repo:

```sh
git fetch origin
git checkout stage3/mongoose-self-trial
git pull origin stage3/mongoose-self-trial
```

Then open this folder: `stage3/handoff/`.

## What the harness does

You give it your target and three limits. It asks the model what to do
next, runs that one step, and shows the model what happened. It stops when
the model says it is done, or when a limit is hit.

One run produces one candidate. That candidate is not a confirmed finding.
Your Stage 2 oracle checks it afterwards. The check stays outside the harness.

## What you set up

1. Install the Python packages in `KICKSTART.md`.
2. Copy `stage2/.env.example` to `.env` at the repo root.
3. Put the key you receive separately into `OPENROUTER_API_KEY`. Leave
   `OPENROUTER_MODEL` empty. Do not commit `.env`. Do not send the key back
   in git.
4. Copy `stage3/targets/TEMPLATE.yaml` to a file for your target. Point it
   at your source tree and at the command that sends one saved input to
   your already running Stage 2 service.
5. In that same file, set the three limits: how many model calls, how long
   one reply may be, and how many dollars the run may spend. A first run
   can use 8, 1200, and 0.05.
6. Start your Stage 2 service yourself. The harness does not start it.
7. Send one normal input through that same command. This spends nothing.
8. From `stage3/`, run the harness on your YAML file. The exact command is
   in `KICKSTART.md`.
9. Read `stage3/results/run-001/`. The useful files are `run.yaml`,
   `usage.jsonl`, `candidate.json`, and `scratch/`. One cost row is added
   to `stage3/results/cost_log.csv`.
10. Later, check the saved input with your own Stage 2 oracle. Until you
    do, the result stays `pending`.

`KICKSTART.md` is the full command list, written so you or an assistant can
follow it on any target. `SELF_TRIAL_RECORD.md` is our first run, including
a candidate that failed the oracle.

## The key

The key is not in this repo. Each person puts their own copy in `.env` on
their own machine. One shared balance pays for every run. Keep the three
limits in your YAML. A run on `openai/gpt-4o-mini` at those limits costs a
fraction of a cent. Raising the dollar limit or switching to a larger model
is what spends the balance.
