<?php

// autoload_static.php @generated by Composer

namespace Composer\Autoload;

class ComposerStaticInitb0e4e69e4a12f7cbb062c33891b6cd30
{
    public static $prefixLengthsPsr4 = array (
        'F' => 
        array (
            'Firebase\\JWT\\' => 13,
        ),
        'D' => 
        array (
            'Dell\\Htdocs\\' => 12,
        ),
    );

    public static $prefixDirsPsr4 = array (
        'Firebase\\JWT\\' => 
        array (
            0 => __DIR__ . '/..' . '/firebase/php-jwt/src',
        ),
        'Dell\\Htdocs\\' => 
        array (
            0 => __DIR__ . '/../..' . '/src',
        ),
    );

    public static $classMap = array (
        'Composer\\InstalledVersions' => __DIR__ . '/..' . '/composer/InstalledVersions.php',
    );

    public static function getInitializer(ClassLoader $loader)
    {
        return \Closure::bind(function () use ($loader) {
            $loader->prefixLengthsPsr4 = ComposerStaticInitb0e4e69e4a12f7cbb062c33891b6cd30::$prefixLengthsPsr4;
            $loader->prefixDirsPsr4 = ComposerStaticInitb0e4e69e4a12f7cbb062c33891b6cd30::$prefixDirsPsr4;
            $loader->classMap = ComposerStaticInitb0e4e69e4a12f7cbb062c33891b6cd30::$classMap;

        }, null, ClassLoader::class);
    }
}