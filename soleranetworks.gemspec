# Generated by jeweler
# DO NOT EDIT THIS FILE DIRECTLY
# Instead, edit Jeweler::Tasks in Rakefile, and run the gemspec command
# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{soleranetworks}
  s.version = "0.1.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["fracBlend"]
  s.date = %q{2010-03-24}
  s.default_executable = %q{solera_get}
  s.description = %q{Solera Neworks API gem}
  s.email = %q{gbelknap@soleranetworks.com}
  s.executables = ["solera_get"]
  s.extra_rdoc_files = [
    "LICENSE",
     "README.rdoc"
  ]
  s.files = [
    ".document",
     ".gitignore",
     "LICENSE",
     "README.rdoc",
     "Rakefile",
     "VERSION",
     "bin/solera_get",
     "lib/soleranetworks.rb",
     "soleranetworks.gemspec",
     "test/helper.rb",
     "test/test_soleranetworks.rb"
  ]
  s.homepage = %q{http://github.com/fracBlend/soleranetworks}
  s.rdoc_options = ["--charset=UTF-8"]
  s.require_paths = ["lib"]
  s.requirements = ["Solera Networks DS (Appliance or VM), SoleraOS v4.x or greater"]
  s.rubygems_version = %q{1.3.6}
  s.summary = %q{Solera Networks API gem}
  s.test_files = [
    "test/helper.rb",
     "test/test_soleranetworks.rb"
  ]

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    else
      s.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
    end
  else
    s.add_dependency(%q<thoughtbot-shoulda>, [">= 0"])
  end
end

