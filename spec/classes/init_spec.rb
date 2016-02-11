require 'spec_helper'
describe 'cffirehol' do

  context 'with defaults for all parameters' do
    it { should contain_class('cffirehol') }
  end
end
