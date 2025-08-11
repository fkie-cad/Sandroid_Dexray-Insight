#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Known Library Signatures Database

Contains known library signatures for similarity-based detection.
In a full implementation, this would be loaded from a comprehensive
database of library signatures obtained through static analysis.

Phase 6.5 TDD Refactoring: Extracted from monolithic library_detection.py
"""

from typing import Dict, Any


def get_known_library_signatures() -> Dict[str, Dict[str, Any]]:
    """
    Get known library signatures for similarity matching
    
    In a full implementation, this would load from a comprehensive database
    of library signatures. For now, we provide some basic signatures.
    
    Returns:
        Dictionary of library signatures with method patterns, call chains, and class info
    """
    return {
        'OkHttp3': {
            'methods': {
                'okhttp3.OkHttpClient.newCall': ['invoke-virtual', 'move-result-object'],
                'okhttp3.Request$Builder.build': ['invoke-virtual', 'move-result-object'],
                'okhttp3.Response.body': ['invoke-virtual', 'move-result-object']
            },
            'call_chains': {
                'okhttp3.Call.execute': ['okhttp3.RealCall.execute'],
                'okhttp3.Call.enqueue': ['okhttp3.RealCall.enqueue']
            },
            'classes': {
                'okhttp3.OkHttpClient': {'methods': 20, 'fields': 5},
                'okhttp3.Request': {'methods': 8, 'fields': 3},
                'okhttp3.Response': {'methods': 15, 'fields': 4}
            }
        },
        'Retrofit2': {
            'methods': {
                'retrofit2.Retrofit$Builder.build': ['invoke-virtual', 'move-result-object'],
                'retrofit2.Call.execute': ['invoke-interface', 'move-result-object']
            },
            'call_chains': {
                'retrofit2.Retrofit.create': ['java.lang.reflect.Proxy.newProxyInstance']
            },
            'classes': {
                'retrofit2.Retrofit': {'methods': 12, 'fields': 6},
                'retrofit2.Call': {'methods': 4, 'fields': 0}
            }
        },
        'Glide': {
            'methods': {
                'com.bumptech.glide.Glide.with': ['invoke-static', 'move-result-object'],
                'com.bumptech.glide.RequestManager.load': ['invoke-virtual', 'move-result-object']
            },
            'call_chains': {
                'com.bumptech.glide.RequestManager.load': ['com.bumptech.glide.DrawableTypeRequest.into']
            },
            'classes': {
                'com.bumptech.glide.Glide': {'methods': 25, 'fields': 8},
                'com.bumptech.glide.RequestManager': {'methods': 18, 'fields': 4}
            }
        },
        'RxJava2': {
            'methods': {
                'io.reactivex.Observable.subscribe': ['invoke-virtual', 'move-result-object'],
                'io.reactivex.schedulers.Schedulers.io': ['invoke-static', 'move-result-object']
            },
            'call_chains': {
                'io.reactivex.Observable.subscribeOn': ['io.reactivex.Observable.observeOn'],
                'io.reactivex.Observable.map': ['io.reactivex.Observable.subscribe']
            },
            'classes': {
                'io.reactivex.Observable': {'methods': 50, 'fields': 8},
                'io.reactivex.Scheduler': {'methods': 12, 'fields': 2}
            }
        },
        'Dagger2': {
            'methods': {
                'dagger.Component': ['invoke-interface'],
                'dagger.Provides': ['invoke-virtual']
            },
            'call_chains': {
                'dagger.android.AndroidInjection.inject': ['dagger.android.DispatchingAndroidInjector.inject']
            },
            'classes': {
                'dagger.android.AndroidInjection': {'methods': 8, 'fields': 1},
                'dagger.Component': {'methods': 1, 'fields': 0}
            }
        },
        'Gson': {
            'methods': {
                'com.google.gson.Gson.toJson': ['invoke-virtual', 'move-result-object'],
                'com.google.gson.Gson.fromJson': ['invoke-virtual', 'move-result-object']
            },
            'call_chains': {
                'com.google.gson.GsonBuilder.create': ['com.google.gson.Gson.<init>']
            },
            'classes': {
                'com.google.gson.Gson': {'methods': 20, 'fields': 10},
                'com.google.gson.GsonBuilder': {'methods': 15, 'fields': 8}
            }
        },
        'Butterknife': {
            'methods': {
                'butterknife.ButterKnife.bind': ['invoke-static'],
                'butterknife.OnClick': ['invoke-interface']
            },
            'call_chains': {
                'butterknife.ButterKnife.bind': ['butterknife.ButterKnife.findAndBind']
            },
            'classes': {
                'butterknife.ButterKnife': {'methods': 25, 'fields': 5},
                'butterknife.Unbinder': {'methods': 1, 'fields': 0}
            }
        },
        'EventBus': {
            'methods': {
                'org.greenrobot.eventbus.EventBus.getDefault': ['invoke-static', 'move-result-object'],
                'org.greenrobot.eventbus.EventBus.register': ['invoke-virtual'],
                'org.greenrobot.eventbus.EventBus.post': ['invoke-virtual']
            },
            'call_chains': {
                'org.greenrobot.eventbus.EventBus.register': ['org.greenrobot.eventbus.SubscriberMethodFinder.findSubscriberMethods']
            },
            'classes': {
                'org.greenrobot.eventbus.EventBus': {'methods': 30, 'fields': 12},
                'org.greenrobot.eventbus.Subscribe': {'methods': 1, 'fields': 0}
            }
        },
        'Picasso': {
            'methods': {
                'com.squareup.picasso.Picasso.with': ['invoke-static', 'move-result-object'],
                'com.squareup.picasso.Picasso.load': ['invoke-virtual', 'move-result-object']
            },
            'call_chains': {
                'com.squareup.picasso.RequestCreator.into': ['com.squareup.picasso.Picasso.enqueueAndSubmit']
            },
            'classes': {
                'com.squareup.picasso.Picasso': {'methods': 35, 'fields': 15},
                'com.squareup.picasso.RequestCreator': {'methods': 20, 'fields': 6}
            }
        },
        'Timber': {
            'methods': {
                'timber.log.Timber.plant': ['invoke-static'],
                'timber.log.Timber.d': ['invoke-static']
            },
            'call_chains': {
                'timber.log.Timber.plant': ['timber.log.Timber.Forest.plant']
            },
            'classes': {
                'timber.log.Timber': {'methods': 40, 'fields': 3},
                'timber.log.Timber$Tree': {'methods': 8, 'fields': 0}
            }
        }
    }