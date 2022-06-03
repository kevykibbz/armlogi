from pathlib import Path
import environ
import os
env=environ.Env()
environ.Env.read_env()
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.2/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!

SECRET_KEY =env('SECRET_KEY')
# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

#ALLOWED_HOSTS = ['192.168.43.253']
ALLOWED_HOSTS = ['armlogi.herokuapp.com','127.0.0.1','localhost']

AUTHENTICATION_BACKENDS = [
    # Needed to login by username in Django admin, regardless of `allauth`
    'django.contrib.auth.backends.ModelBackend',

    # `allauth` specific authentication methods, such as login by e-mail
    'allauth.account.auth_backends.AuthenticationBackend',
    #'axes.backends.AxesBackend',
]

# Application definition

INSTALLED_APPS = [
    'whitenoise.runserver_nostatic',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'installation.apps.InstallationConfig',
    'django.contrib.humanize',
    'phonenumber_field',
    'errors.apps.ErrorsConfig',
    'manager.apps.ManagerConfig',
    'django.contrib.sites', #social app 
    'allauth', #social app
    'allauth.account', #social app
    'allauth.socialaccount', #social app
    'allauth.socialaccount.providers.google', #social app
    'allauth.socialaccount.providers.twitter', #social app
    'allauth.socialaccount.providers.github', #social app
    'django_cleanup.apps.CleanupConfig',
]

SITE_ID = 2

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'saas.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [os.path.join(BASE_DIR,'templates')],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
                'saas.site_constants.export_vars',
            ],
        },
    },
]

WSGI_APPLICATION = 'saas.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.2/ref/settings/#databases


# DATABASES = {
#     "default": {
#         "ENGINE": "djongo",
#         "NAME":env('MONGO_DB_NAME'),
#         "ENFORCE-SCHEMA":False,
#         "CLIENT": {
#             "host":env('MONGO_DB_HOST'),
#             "port": 27017,
#             "username":env('MONGO_DB_USERNAME'),
#             "password":env('MONGO_DB_PASSWORD'),
#         },
#     },
# }

# DATABASES = {
#     'default': {
#          'ENGINE': 'django.db.backends.sqlite3',
#         'NAME':'admino',
#     }
#  }

# DATABASES = {
#     'default': {
#         'ENGINE': 'djongo',
#         'NAME':'admino',
#         'ENFORCE-SCHEMA':False,
#     }
#  }
#postgres://xdpajrqtvijfka:44def245e34f9569a2a293b8ca0b6c2e8fcb9c0a897c1b9a5c5d137e0b49c4a0@ec2-34-236-94-53.compute-1.amazonaws.com:5432/df2pholl515ae7

DATABASES = {
   'default': {
       'ENGINE': 'django.db.backends.postgresql',
       'NAME':env('DATABASE_NAME'),
       'HOST':env('DATABASE_HOST'),
       'USER':env('DATABASE_USER'),
       'PASSWORD':env('DATABASE_PASSWORD'),
   }
}

# DATABASES = {
#    'default': 
#             {

#                 'ENGINE': 'mysql.connector.django',
#                 'NAME':'admino',
#                 'USER':'root',
#                 'PASSWORD':'',
#                 'HOST':'localhost',
#                 'PORT':3306,
#                 'OPTIONS':
#                 {
#                     'autocommit':True,
#                 },
#             }
# }

# Password validation
# https://docs.djangoproject.com/en/3.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS':
        {
            'min_length':6,
        },
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
    {
        'NAME':'manager.validators.NumberValidator',
        'OPTIONS':
        {
            'min_length':2,
        },
    },
    {
        'NAME':'manager.validators.UpperCaseValidator',
    },
    {
        'NAME':'manager.validators.LowerCaseValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.2/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'America/Los_Angeles'

USE_I18N = True

USE_L10N = True

USE_TZ = True


#login
LOGIN_URL='/'
LOGIN_REDIRECT_URL='/dashboard/'
LOGOUT_REDIRECT_URL='/'
# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.2/howto/static-files/

STATIC_URL = '/static/'
MEDIA='/media/'

#STATICFILES_STORAGE='whitenoise.storage.CompressedManifestStaticFilesStorage'
# Default primary key field type
# https://docs.djangoproject.com/en/3.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

if DEBUG:
    STATICFILES_DIRS=[os.path.join(BASE_DIR,'static')]
else:
    STATIC_ROOT=os.path.join(BASE_DIR,'static')

#MEDIA_ROOT='/home2/chillcas/chillcash.co.ke/media'
MEDIA_ROOT=os.path.join(BASE_DIR,'media')


BASE_URL=env('BASE_URL')


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST=env('EMAIL_HOST')
EMAIL_HOST_USER=env('EMAIL_USER')
EMAIL_HOST_PASSWORD=env('EMAIL_PASSWORD')
EMAIL_USE_TLS=True
EMAIL_PORT=587 
DEFAULT_FROM_EMAIL=EMAIL_HOST_USER


#cache
CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://127.0.0.1:6379/1",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
        }
    }
}
