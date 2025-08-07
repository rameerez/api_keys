begin
  require "bundler/setup"
rescue LoadError
  puts "You must `gem install bundler` and `bundle install` to run rake tasks"
end

require "bundler/gem_tasks"

require "rdoc/task"

RDoc::Task.new(:rdoc) do |rdoc|
  rdoc.rdoc_dir = "rdoc"
  rdoc.title = "Pay"
  rdoc.options << "--line-numbers"
  rdoc.rdoc_files.include("README.md")
  rdoc.rdoc_files.include("lib/**/*.rb")
end

# Removed loading of engine tasks to avoid pulling in dummy app/vendor tests
# APP_RAKEFILE = File.expand_path("test/dummy/Rakefile", __dir__)
# load "rails/tasks/engine.rake"

# Removed Rails statistics task; not needed for gem tests
# load "rails/tasks/statistics.rake"

require "rake/testtask"

# Ensure any test task created by engine.rake is cleared so only this suite runs
Rake::Task[:test].clear if Rake::Task.task_defined?(:test)

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.verbose = false
  t.test_files = FileList['test/**/*_test.rb'].exclude('test/dummy/**/*')
end

task default: :test
