require 'gitlab-dangerfiles'

# see https://docs.gitlab.com/ee/development/dangerbot.html#enable-danger-on-a-project
# see https://gitlab.com/gitlab-org/ruby/gems/gitlab-dangerfiles
Gitlab::Dangerfiles.for_project(self) do |dangerfiles|
  # Import all plugins from the gem
  dangerfiles.import_plugins

  # Import a defined set of danger rules
  dangerfiles.import_dangerfiles(only: %w[changelog metadata type_label z_add_labels z_retry_link])
end
