# Prompt Injection

> A technique where specific prompts or cues are inserted into the input data to guide the output of a machine learning model, specifically in the field of natural language processing (NLP).

## Summary

* [Tools](#tools)
* [Applications](#applications)
    * [Story Generation](#story-generation)
    * [Potential Misuse](#potential-misuse)
* [System Prompt](#system-prompt)
* [Direct Prompt Injection](#direct-prompt-injection)
* [Indirect Prompt Injection](#indirect-prompt-injection)
* [References](#references)

## Tools

Simple list of tools that can be targeted by "Prompt Injection".
They can also be used to generate interesting prompts.

* [ChatGPT - OpenAI](https://chat.openai.com)
* [Gemini - Google](https://gemini.google.com)
* [Le Chat - Mistral AI](https://chat.mistral.ai)
* [Claude - Anthropic](https://claude.ai)

List of "payloads" prompts

* [TakSec/Prompt-Injection-Everywhere](https://github.com/TakSec/Prompt-Injection-Everywhere) - Prompt Injections Everywhere
* [NVIDIA/garak](https://github.com/NVIDIA/garak) - LLM vulnerability scanner
* [Chat GPT "DAN" (and other "Jailbreaks")](https://gist.github.com/coolaj86/6f4f7b30129b0251f61fa7baaa881516)
* [Jailbreak Chat](https://web.archive.org/web/20230217030558/https://www.jailbreakchat.com/)
* [Inject My PDF](https://kai-greshake.de/posts/inject-my-pdf)
* [LLM Hacking Database](https://github.com/pdparchitect/llm-hacking-database)
* [LLM Fuzzer](https://github.com/mnns/LLMFuzzer)

Tools to identify and attack Large Language Models.

* [praetorian-inc/julius](https://github.com/praetorian-inc/julius) - Simple LLM service identification - translate IP:Port to Ollama, vLLM, LiteLLM, or 15+ other AI services in seconds
* [praetorian-inc/augustus](https://github.com/praetorian-inc/augustus) - LLM security testing framework for detecting prompt injection, jailbreaks, and adversarial attacks — 190+ probes, 28 providers, single Go binary
* [promptfoo/promptfoo](https://github.com/promptfoo/promptfoo) - Test your prompts, agents, and RAGs. AI Red teaming, pentesting, and vulnerability scanning for LLMs.
* [rudrasatani13/cot-redteam-agent](https://github.com/rudrasatani13/cot-redteam-agent) - CLI and Python API for red-teaming visible LLM reasoning and agent actions, with honest scoring and a simulated Proof-of-Action agent world
