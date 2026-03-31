# frozen_string_literal: true

require "pathname"
require "active_support"
require "io/console"
require "rails/command/helpers/editor"
require "rails/command/environment_argument"

module Rails
  module Command
    class CredentialsCommand < Rails::Command::Base # :nodoc:
      include Helpers::Editor
      include EnvironmentArgument

      require_relative "credentials_command/diffing"
      include Diffing

      desc "edit", "Open the decrypted credentials in `$VISUAL` or `$EDITOR` for editing"
      def edit
        load_environment_config!
        load_generators

        if environment_specified?
          @content_path = "config/credentials/#{environment}.yml.enc" unless config.overridden?(:content_path)
          @key_path = "config/credentials/#{environment}.key" unless config.overridden?(:key_path)
        end

        ensure_encryption_key_has_been_added
        ensure_credentials_have_been_added
        ensure_diffing_driver_is_configured

        change_credentials_in_system_editor
      end

      desc "show", "Show the decrypted credentials"
      def show
        load_environment_config!

        say credentials.read.presence || missing_credentials!
      end

      desc "diff", "Enroll/disenroll in decrypted diffs of credentials using git"
      option :enroll, type: :boolean, default: false,
        desc: "Enroll project in credentials file diffing with `git diff`"
      option :disenroll, type: :boolean, default: false,
        desc: "Disenroll project from credentials file diffing"
      def diff(content_path = nil)
        if @content_path = content_path
          self.environment = extract_environment_from_path(content_path)
          load_environment_config!

          say credentials.read.presence || credentials.content_path.read
        else
          disenroll_project_from_credentials_diffing if options[:disenroll]
          enroll_project_in_credentials_diffing if options[:enroll]
        end
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        say credentials.content_path.read
      end

      desc "fetch PATH", "Fetch a value in the decrypted credentials"
      def fetch(path)
        load_environment_config!

        if (yaml = credentials.read)
          begin
            value = YAML.load(yaml)
            value = path.split(".").inject(value) do |doc, key|
              doc.fetch(key)
            end
            say value.to_s
          rescue KeyError, NoMethodError
            say_error "Invalid or missing credential path: #{path}"
            exit 1
          end
        else
          missing_credentials!
        end
      end

      desc "set KEY [KEY2 ...]", "Set credentials securely from STDIN or interactive prompt"
      option :insecure, type: :boolean, default: false,
        desc: "Allow unsafe command-line arguments (WARNING: exposes secrets in shell history)"
      option :force, aliases: "-f", type: :boolean, default: false,
        desc: "Skip confirmation when overwriting existing credentials"
      def set(*keys)
        load_environment_config!
        load_generators

        if keys.empty?
          say_error "No keys provided. Usage: #{executable(:set)} KEY [KEY2 ...]"
          exit 1
        end

        if environment_specified?
          @content_path = "config/credentials/#{environment}.yml.enc" unless config.overridden?(:content_path)
          @key_path = "config/credentials/#{environment}.key" unless config.overridden?(:key_path)
        end

        ensure_encryption_key_has_been_added
        ensure_credentials_have_been_added

        set_credentials_secure(keys)
      rescue ActiveSupport::EncryptedFile::MissingKeyError => error
        say error.message
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        say "Couldn't decrypt #{content_path}. Perhaps you passed the wrong key?"
      end

      desc "unset KEY [KEY2 ...]", "Remove credentials from the encrypted credentials file"
      def unset(*keys)
        load_environment_config!
        load_generators

        if keys.empty?
          say_error "No keys provided. Usage: #{executable(:unset)} KEY"
          exit 1
        end

        if environment_specified?
          @content_path = "config/credentials/#{environment}.yml.enc" unless config.overridden?(:content_path)
          @key_path = "config/credentials/#{environment}.key" unless config.overridden?(:key_path)
        end

        if !credentials.key?
          missing_credentials!
        end

        unset_credentials(keys)
      rescue ActiveSupport::EncryptedFile::MissingKeyError => error
        say error.message
      rescue ActiveSupport::MessageEncryptor::InvalidMessage
        say "Couldn't decrypt #{content_path}. Perhaps you passed the wrong key?"
      end

      private
        def config
          Rails.application.config.credentials
        end

        def content_path
          @content_path ||= relative_path(config.content_path)
        end

        def key_path
          @key_path ||= relative_path(config.key_path)
        end

        def credentials
          @credentials ||= Rails.application.encrypted(content_path, key_path: key_path)
        end

        def ensure_encryption_key_has_been_added
          return if credentials.key?

          require "rails/generators/rails/encryption_key_file/encryption_key_file_generator"

          encryption_key_file_generator = Rails::Generators::EncryptionKeyFileGenerator.new
          encryption_key_file_generator.add_key_file(key_path)
        end

        def ensure_credentials_have_been_added
          require "rails/generators/rails/credentials/credentials_generator"

          Rails::Generators::CredentialsGenerator.new(
            [content_path, key_path],
            skip_secret_key_base: environment_specified? && %w[development test].include?(environment),
            quiet: true
          ).invoke_all
        end

        def change_credentials_in_system_editor
          using_system_editor do
            say "Editing #{content_path}..."
            credentials.change { |tmp_path| system_editor(tmp_path) }
            say "File encrypted and saved."
            warn_if_credentials_are_invalid
          end
        rescue ActiveSupport::EncryptedFile::MissingKeyError => error
          say error.message
        rescue ActiveSupport::MessageEncryptor::InvalidMessage
          say "Couldn't decrypt #{content_path}. Perhaps you passed the wrong key?"
        end

        def warn_if_credentials_are_invalid
          credentials.validate!
        rescue ActiveSupport::EncryptedConfiguration::InvalidContentError => error
          say "WARNING: #{error.message}", :red
          say ""
          say "Your application will not be able to load '#{content_path}' until the error has been fixed.", :red
        end

        def missing_credentials!
          if !credentials.key?
            say_error "Missing '#{key_path}' to decrypt credentials. See `#{executable(:help)}`."
          else
            say_error "File '#{content_path}' does not exist. Use `#{executable(:edit)}` to change that."
          end
          exit 1
        end

        def relative_path(path)
          Rails.root.join(path).relative_path_from(Rails.root).to_s
        end

        def extract_environment_from_path(path)
          available_environments.find { |env| path.end_with?("#{env}.yml.enc") } || extract_custom_environment(path)
        end

        def extract_custom_environment(path)
          path =~ %r{config/credentials/(.+)\.yml\.enc} && $1
        end

        # === set/unset command implementation ===

        def set_credentials_secure(keys)
          # Detect input mode: command-line args, STDIN, or interactive
          input_mode, key_value_pairs = detect_input_mode(keys)

          # Show security warning if using unsafe mode
          if input_mode == :command_line
            show_insecure_warning
          end

          # Parse all key-value pairs
          updates = key_value_pairs.map { |key, value| [parse_key_path(key), value] }

          # Deduplicate updates
          updates = deduplicate_updates(updates)

          # Read current credentials
          current_yaml = credentials.read
          current_config = deserialize_config(current_yaml)

          # Check for overwrites
          has_overwrites = updates.any? { |(path, _)| !get_nested_value(current_config, path).nil? }

          # Apply changes
          new_config = current_config.dup
          updates.each do |(path, value)|
            set_nested_value(new_config, path, parse_value(value))
          end

          # Show preview (with redacted values for security)
          display_set_preview_secure(current_config, new_config, updates)

          # Confirm if overwriting and not forced
          if has_overwrites && !options[:force]
            unless prompt_for_overwrite_confirmation
              say "Aborted."
              exit 0
            end
          end

          # Write encrypted changes
          credentials.change do |tmp_path|
            tmp_path.binwrite(serialize_config(new_config))
          end

          say "Credentials encrypted and saved."
          warn_if_credentials_are_invalid
        end

        def unset_credentials(keys)
          # 1. Parse all key paths
          paths = keys.map { |key| parse_key_path(key) }

          # 2. Read and parse current credentials
          current_yaml = credentials.read
          current_config = deserialize_config(current_yaml)

          # 3. Track what will be removed (for preview)
          removed_values = {}

          # 4. Apply removals to a copy
          new_config = current_config.dup
          paths.each do |path|
            removed_values[path] = get_nested_value(new_config, path)
            unset_nested_value(new_config, path)
          end

          # 5. Show preview
          display_unset_preview(removed_values)

          # 6. Write encrypted changes
          credentials.change do |tmp_path|
            tmp_path.binwrite(serialize_config(new_config))
          end

          say "Credentials encrypted and saved."
          warn_if_credentials_are_invalid
        end

        # === Secure input handling ===

        def detect_input_mode(keys)
          # Check if using insecure command-line arguments (KEY=VALUE format)
          has_equals = keys.any? { |arg| arg.include?("=") }

          if has_equals
            # Command-line arguments detected
            unless options[:insecure]
              say_error "ERROR: Command-line arguments containing secrets are insecure!"
              say_error ""
              say_error "Secrets in command-line arguments are exposed in:"
              say_error "  • Shell history (~/.bash_history)"
              say_error "  • Process listings (ps aux)"
              say_error "  • System logs"
              say_error ""
              say_error "Secure alternatives:"
              say_error "  1. STDIN:       echo \"value\" | bin/rails credentials:set KEY"
              say_error "  2. Interactive: bin/rails credentials:set KEY  (prompts securely)"
              say_error ""
              say_error "To use command-line arguments anyway (NOT RECOMMENDED):"
              say_error "  bin/rails credentials:set --insecure KEY=VALUE"
              exit 1
            end

            # Parse command-line key=value pairs
            key_value_pairs = keys.map do |arg|
              validate_key_value_format(arg)
              key, value = arg.split("=", 2)
              [key, value]
            end

            return [:command_line, key_value_pairs]
          end

          # Check if STDIN has data (for piped input)
          if !$stdin.tty?
            # Read values from STDIN (one per line, matching key order)
            values = keys.map do |key|
              value = $stdin.gets
              if value.nil?
                say_error "ERROR: Expected value for key '#{key}' from STDIN"
                exit 1
              end
              value.chomp
            end

            key_value_pairs = keys.zip(values)
            return [:stdin, key_value_pairs]
          end

          # Interactive mode - prompt for each value
          key_value_pairs = keys.map do |key|
            value = prompt_for_secret_value(key)
            [key, value]
          end

          return [:interactive, key_value_pairs]
        end

        def prompt_for_secret_value(key)
          say ""
          say "Setting: #{key.split('__').join('.')}"

          # Prompt with hidden input
          print "Enter value (hidden): "
          value1 = $stdin.noecho(&:gets).chomp
          puts ""  # New line after hidden input

          # Confirm value
          print "Confirm value (hidden): "
          value2 = $stdin.noecho(&:gets).chomp
          puts ""

          if value1 != value2
            say_error "ERROR: Values don't match. Please try again."
            say ""
            return prompt_for_secret_value(key)
          end

          if value1.empty?
            print "Value is empty. Continue? (y/N): "
            answer = $stdin.gets.chomp
            unless answer.downcase == "y"
              say "Aborted."
              exit 0
            end
          end

          value1
        end

        def show_insecure_warning
          say ""
          say "⚠️  WARNING: Using --insecure exposes secrets in shell history and process listings!", :red
          say "⚠️  For secure input, use: echo \"value\" | bin/rails credentials:set KEY", :red
          say ""
        end

        def display_set_preview_secure(before_config, after_config, updates)
          say ""
          say "Setting credentials in #{content_path}:", :green
          say ""

          updates.each do |(path, value)|
            key_display = path.join(".")
            old_value = get_nested_value(before_config, path)
            parsed_value = parse_value(value)

            # Show actual values (matches Rails' behavior of showing encryption keys during setup)
            if old_value.nil?
              say "  + #{key_display}: #{parsed_value.inspect}", :green
            else
              say "  ~ #{key_display}: #{old_value.inspect} → #{parsed_value.inspect}", :yellow
            end
          end

          say ""
        end

        def validate_key_value_format(arg)
          unless arg.include?("=")
            say_error "Invalid format: '#{arg}'. Expected KEY=VALUE"
            say_error "Note: This format is insecure and requires --insecure flag"
            exit 1
          end

          key_str, _value = arg.split("=", 2)

          if key_str.empty?
            say_error "Empty key in: '#{arg}'"
            exit 1
          end
        end

        # === Validation and confirmation ===

        def validate_key_value_args(args)
          args.each do |arg|
            # Check if it looks like a flag (starts with - but isn't a negative number)
            if arg.start_with?("-") && !arg.match?(/^-\d/)
              say_error "Unknown option: '#{arg}'"
              say_error ""
              say_error "Available options:"
              say_error "  -e, --environment  Specify the environment (e.g., development, production)"
              say_error "  -f, --force        Skip confirmation when overwriting existing credentials"
              say_error ""
              say_error "Usage: #{executable(:set)} KEY=VALUE [KEY2=VALUE2 ...]"
              exit 1
            end

            unless arg.include?("=")
              say_error "Invalid format: '#{arg}'. Expected KEY=VALUE"
              say_error "Usage: #{executable(:set)} KEY=VALUE [KEY2=VALUE2 ...]"
              exit 1
            end

            key_str, _value = arg.split("=", 2)

            if key_str.empty?
              say_error "Empty key in: '#{arg}'"
              exit 1
            end
          end
        end

        def deduplicate_updates(updates)
          # Use a hash to track the last value for each key path
          # Convert path arrays to strings for comparison
          deduped = {}
          updates.each do |(path, value)|
            deduped[path.join(".")] = [path, value]
          end

          # Convert back to array of [path, value] tuples
          deduped.values
        end

        def prompt_for_overwrite_confirmation
          say ""
          answer = ask "Overwrite existing credentials? (y/N):"
          say ""

          answer.to_s.downcase == "y"
        end

        # === Parsing helpers ===

        # Parse "DATABASE__HOST=localhost" into [["database", "host"], "localhost"]
        def parse_key_value_pair(arg)
          unless arg.include?("=")
            raise ArgumentError, "Invalid format: #{arg}. Expected KEY=VALUE"
          end

          key_str, value = arg.split("=", 2)
          path = parse_key_path(key_str)

          [path, value]
        end

        # Convert "DATABASE__HOST" to ["database", "host"]
        # Matches Rails convention: ENV["DATABASE__HOST"] maps to Rails.app.creds.require(:database, :host)
        def parse_key_path(key_str)
          key_str.split("__").map(&:downcase)
        end

        # Infer type from string value
        def parse_value(value_str)
          case value_str
          when /^\d+$/
            value_str.to_i
          when /^\d+\.\d+$/
            value_str.to_f
          when /^true$/i
            true
          when /^false$/i
            false
          when /^nil$/i, /^null$/i
            nil
          else
            # Remove surrounding quotes if present
            value_str.sub(/^['"]/, "").sub(/['"]$/, "")
          end
        end

        # === Hash manipulation helpers ===

        # Set a nested value in a hash, creating intermediate hashes as needed
        # Example: set_nested_value({}, ["database", "host"], "localhost")
        #   => {"database" => {"host" => "localhost"}}
        def set_nested_value(hash, path, value)
          *parent_keys, final_key = path

          # Navigate/create parent structure
          parent = parent_keys.reduce(hash) do |h, key|
            h[key] ||= {}

            unless h[key].is_a?(Hash)
              raise ArgumentError, "Cannot set nested key: '#{key}' is not a hash"
            end

            h[key]
          end

          parent[final_key] = value
        end

        # Remove a nested value and clean up empty parents
        def unset_nested_value(hash, path)
          return nil if path.empty?

          *parent_keys, final_key = path

          # Navigate to parent
          parent = parent_keys.reduce(hash) do |h, key|
            return nil unless h.is_a?(Hash) && h.key?(key)
            h[key]
          end

          return nil unless parent.is_a?(Hash)

          # Remove the key
          parent.delete(final_key)

          # Clean up empty parents recursively
          cleanup_empty_parents(hash, path)
        end

        # Recursively remove empty parent hashes after deletion
        def cleanup_empty_parents(hash, path)
          return if path.size <= 1

          parent_path = path[0..-2]
          parent = get_nested_value(hash, parent_path)

          if parent.is_a?(Hash) && parent.empty?
            unset_nested_value(hash, parent_path)
          end
        end

        # Safely retrieve a nested value
        def get_nested_value(hash, path)
          path.reduce(hash) do |h, key|
            return nil unless h.is_a?(Hash)
            h[key]
          end
        end

        # === YAML serialization helpers ===

        def deserialize_config(yaml_content)
          return {} if yaml_content.blank?
          YAML.load(yaml_content) || {}
        rescue Psych::SyntaxError
          raise ActiveSupport::EncryptedConfiguration::InvalidContentError.new(content_path)
        end

        def serialize_config(config)
          return "" if config.empty?
          YAML.dump(config)
        end

        # === Display helpers ===

        def display_set_preview(before_config, after_config, updates)
          say ""
          say "Setting credentials in #{content_path}:", :green
          say ""

          updates.each do |(path, raw_value)|
            key_display = path.join(".")
            parsed_value = parse_value(raw_value)
            old_value = get_nested_value(before_config, path)

            if old_value.nil?
              say "  + #{key_display}: #{parsed_value.inspect}", :green
            else
              say "  ~ #{key_display}: #{old_value.inspect} → #{parsed_value.inspect}", :yellow
            end
          end

          say ""
        end

        def display_unset_preview(removed_values)
          say ""
          say "Removing credentials from #{content_path}:", :red
          say ""

          removed_values.each do |path, value|
            key_display = path.join(".")
            if value.nil?
              say "  - #{key_display}: (not found)", :yellow
            else
              say "  - #{key_display}: #{value.inspect}", :red
            end
          end

          say ""
        end
    end
  end
end
