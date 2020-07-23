.PHONY: ruby
ruby:
	@ if [ ! $$(which ruby) ]; then \
			echo "Please install ruby version 2.5.0 or higher"; \
		fi

.PHONY: bundle
bundle: ruby
	@ if [ ! $$(which bundle) ]; then \
			echo "Please install bundle: `gem install bundler`"; \
		fi

vendor/bundle: bundle
	bundle config set --local path 'vendor/bundle'
	bundle install

.PHONY: serve
serve: vendor/bundle
	bundle exec jekyll serve
