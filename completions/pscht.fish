# Auto-generated base completions from swift-argument-parser
# plus dynamic namespace/key completions

function __pscht_should_offer_completions_for_flags_or_options -a expected_commands
    set -l non_repeating_flags_or_options $argv[2..]

    set -l non_repeating_flags_or_options_absent 0
    set -l positional_index 0
    set -l commands
    __pscht_parse_tokens
    test "$commands" = "$expected_commands"; and return $non_repeating_flags_or_options_absent
end

function __pscht_should_offer_completions_for_positional -a expected_commands expected_positional_index positional_index_comparison
    if test -z $positional_index_comparison
        set positional_index_comparison -eq
    end

    set -l non_repeating_flags_or_options
    set -l non_repeating_flags_or_options_absent 0
    set -l positional_index 0
    set -l commands
    __pscht_parse_tokens
    test "$commands" = "$expected_commands" -a \( "$positional_index" "$positional_index_comparison" "$expected_positional_index" \)
end

function __pscht_parse_tokens -S
    set -l unparsed_tokens (__pscht_tokens -pc)
    set -l present_flags_and_options

    switch $unparsed_tokens[1]
    case 'pscht'
        __pscht_parse_subcommand 0 'h/help'
        switch $unparsed_tokens[1]
        case 'set'
            __pscht_parse_subcommand -r 2 'no-bio' 'h/help'
        case 'get'
            __pscht_parse_subcommand 2 'no-bio' 'h/help'
        case 'run'
            __pscht_parse_subcommand -r 2 'no-bio' 'h/help'
        case 'list'
            __pscht_parse_subcommand 1 'h/help'
        case 'remove'
            __pscht_parse_subcommand 2 'h/help'
        case 'help'
            __pscht_parse_subcommand -r 1
        end
    end
end

function __pscht_tokens
    if test (string split -m 1 -f 1 -- . "$FISH_VERSION") -gt 3
        commandline --tokens-raw $argv
    else
        commandline -o $argv
    end
end

function __pscht_parse_subcommand -S -a positional_count
    argparse -s r -- $argv
    set -l option_specs $argv[2..]

    set -a commands $unparsed_tokens[1]
    set -e unparsed_tokens[1]

    set positional_index 0

    while true
        argparse -sn "$commands" $option_specs -- $unparsed_tokens 2> /dev/null
        set unparsed_tokens $argv
        set positional_index (math $positional_index + 1)

        for non_repeating_flag_or_option in $non_repeating_flags_or_options
            if set -ql _flag_$non_repeating_flag_or_option
                set non_repeating_flags_or_options_absent 1
                break
            end
        end

        if test (count $unparsed_tokens) -eq 0 -o \( -z "$_flag_r" -a "$positional_index" -gt "$positional_count" \)
            break
        end
        set -e unparsed_tokens[1]
    end
end

# --- Dynamic completions for namespaces and keys ---

function __pscht_list_namespaces
    pscht list --no-bio 2>/dev/null
end

function __pscht_get_namespace_from_args
    set -l tokens (commandline -opc)
    # Find the first positional arg after the subcommand (skip flags)
    for i in (seq 3 (count $tokens))
        switch $tokens[$i]
        case '-*'
            continue
        case '*'
            echo $tokens[$i]
            return
        end
    end
end

function __pscht_list_keys
    set -l ns (__pscht_get_namespace_from_args)
    if test -n "$ns"
        pscht list --no-bio $ns 2>/dev/null
    end
end

# --- Base completions ---

complete -c 'pscht' -f
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'set' -d 'Store secrets in a namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'get' -d 'Retrieve a single secret'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'run' -d 'Run a command with secrets as environment variables'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'list' -d 'List namespaces or keys within a namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'remove' -d 'Remove a key or all keys in a namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht" 1' -fa 'help' -d 'Show subcommand help information.'

# Flags
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht set" no-bio' -l 'no-bio' -d 'Skip biometric authentication'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht set" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht get" no-bio' -l 'no-bio' -d 'Skip biometric authentication'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht get" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht run" no-bio' -l 'no-bio' -d 'Skip biometric authentication'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht run" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht list" h help' -s 'h' -l 'help' -d 'Show help information.'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_flags_or_options "pscht remove" h help' -s 'h' -l 'help' -d 'Show help information.'

# Dynamic namespace completions (1st positional arg for set, get, run, list, remove)
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht set" 1' -fa '(__pscht_list_namespaces)' -d 'namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht get" 1' -fa '(__pscht_list_namespaces)' -d 'namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht run" 1' -fa '(__pscht_list_namespaces)' -d 'namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht list" 1' -fa '(__pscht_list_namespaces)' -d 'namespace'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht remove" 1' -fa '(__pscht_list_namespaces)' -d 'namespace'

# Dynamic key completions (2nd positional arg for get, remove; repeating for set)
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht get" 2' -fa '(__pscht_list_keys)' -d 'key'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht remove" 2' -fa '(__pscht_list_keys)' -d 'key'
complete -c 'pscht' -n '__pscht_should_offer_completions_for_positional "pscht set" 2 -ge' -fa '(__pscht_list_keys)' -d 'key'
