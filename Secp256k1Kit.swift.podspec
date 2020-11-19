Pod::Spec.new do |s|
  s.name             = 'Secp256k1Kit.swift'
  s.module_name      = 'Secp256k1Kit'
  s.version          = '1.1'
  s.summary          = 'Crypto secp256k1 library for Swift'

  s.description      = <<-DESC
CryptoSecp256k1 includes crypto functions for signing transactions Swift. It supports secp256k1.
                       DESC

  s.homepage         = 'https://github.com/horizontalsystems/secp256k1-kit-ios'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Horizontal Systems' => 'hsdao@protonmail.ch' }
  s.source           = { git: 'https://github.com/horizontalsystems/secp256k1-kit-ios.git', tag: "#{s.version}" }
  s.social_media_url = 'http://horizontalsystems.io/'

  s.ios.deployment_target = '11.0'
  s.swift_version = '5'

  s.source_files = ['Secp256k1Kit/Classes/**/*', 'Secp256k1Kit/Libraries/include/*.h']

  s.preserve_paths = ['Secp256k1Kit/Libraries']
  s.vendored_libraries  = 'Secp256k1Kit/Libraries/lib/libsecp256k1.a'

  s.user_target_xcconfig = { 'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64' }
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/Secp256k1Kit/Libraries/include"',
    'LIBRARY_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/Secp256k1Kit/Libraries/lib"',
    'EXCLUDED_ARCHS[sdk=iphonesimulator*]' => 'arm64'
  }
end
