<template>
	<cdx-typeahead-search
		:id="id"
		ref="searchForm"
		:class="rootClasses"
		:search-results-label="$i18n( 'searchresults' ).text()"
		:accesskey="searchAccessKey"
		:title="searchTitle"
		:placeholder="searchPlaceholder"
		:aria-label="searchPlaceholder"
		:initial-input-value="searchQuery"
		:button-label="$i18n( 'searchbutton' ).text()"
		:form-action="action"
		:show-thumbnail="showThumbnail"
		:highlight-query="highlightQuery"
		:auto-expand-width="autoExpandWidth"
		:search-results="suggestions"
		:search-footer-url="searchFooterUrl"
		@input="onInput"
		@search-result-click="instrumentation.onSuggestionClick"
		@submit="onSubmit"
	>
		<template #default>
			<input
				type="hidden"
				name="title"
				:value="searchPageTitle"
			>
			<input
				type="hidden"
				name="wprov"
				:value="wprov"
			>
		</template>
		<!-- eslint-disable-next-line vue/no-template-shadow -->
		<template #search-footer-text="{ searchQuery }">
			<span v-i18n-html:vector-searchsuggest-containing="[ searchQuery ]"></span>
		</template>
	</cdx-typeahead-search>
</template>

<script>
/* global SearchSubmitEvent */
const { CdxTypeaheadSearch } = require( '@wikimedia/codex-search' ),
	{ defineComponent, nextTick } = require( 'vue' ),
	client = require( './restSearchClient.js' ),
	restClient = client( mw.config ),
	urlGenerator = require( './urlGenerator.js' )( mw.config ),
	instrumentation = require( './instrumentation.js' );

// @vue/component
module.exports = exports = defineComponent( {
	name: 'App',
	compatConfig: {
		MODE: 3
	},
	compilerOptions: {
		whitespace: 'condense'
	},
	components: { CdxTypeaheadSearch },
	props: {
		id: {
			type: String,
			required: true
		},
		searchPageTitle: {
			type: String,
			default: 'Special:Search'
		},
		autofocusInput: {
			type: Boolean,
			default: false
		},
		action: {
			type: String,
			default: ''
		},
		/** The keyboard shortcut to focus search. */
		// eslint-disable-next-line vue/require-default-prop
		searchAccessKey: {
			type: String
		},
		/** The access key informational tip for search. */
		// eslint-disable-next-line vue/require-default-prop
		searchTitle: {
			type: String
		},
		/** The ghost text shown when no search query is entered. */
		// eslint-disable-next-line vue/require-default-prop
		searchPlaceholder: {
			type: String
		},
		/**
		 * The search query string taken from the server-side rendered input immediately before
		 * client render.
		 */
		// eslint-disable-next-line vue/require-default-prop
		searchQuery: {
			type: String
		},
		showThumbnail: {
			type: Boolean,
			// eslint-disable-next-line vue/no-boolean-default
			default: true
		},
		showDescription: {
			type: Boolean,
			// eslint-disable-next-line vue/no-boolean-default
			default: true
		},
		highlightQuery: {
			type: Boolean,
			// eslint-disable-next-line vue/no-boolean-default
			default: true
		},
		autoExpandWidth: {
			type: Boolean,
			default: false
		}
	},
	data() {
		return {
			// -1 here is the default "active suggestion index".
			wprov: instrumentation.getWprovFromResultIndex( -1 ),

			// Suggestions to be shown in the TypeaheadSearch menu.
			suggestions: [],

			// Link to the search page for the current search query.
			searchFooterUrl: '',

			// Whether to apply a CSS class that disables the CSS transitions on the text input
			disableTransitions: this.autofocusInput,

			instrumentation: instrumentation.listeners
		};
	},
	computed: {
		rootClasses() {
			return {
				'vector-search-box-disable-transitions': this.disableTransitions
			};
		}
	},
	methods: {
		/**
		 * Fetch suggestions when new input is received.
		 *
		 * @param {string} value
		 */
		onInput: function ( value ) {
			const domain = mw.config.get( 'wgVectorSearchHost', location.host ),
				query = value.trim();

			if ( query === '' ) {
				this.suggestions = [];
				this.searchFooterUrl = '';
				return;
			}

			instrumentation.listeners.onFetchStart();

			restClient.fetchByTitle( query, domain, 10, this.showDescription ).fetch
				.then( ( data ) => {
					this.suggestions = data.results;
					this.searchFooterUrl = urlGenerator.generateUrl( query );

					const event = {
						numberOfResults: data.results.length,
						query: query
					};
					instrumentation.listeners.onFetchEnd( event );
				} )
				.catch( () => {
					// TODO: error handling
				} );
		},

		/**
		 * @param {SearchSubmitEvent} event
		 */
		onSubmit( event ) {
			this.wprov = instrumentation.getWprovFromResultIndex( event.index );

			instrumentation.listeners.onSubmit( event );
		}
	},
	mounted() {
		if ( this.autofocusInput ) {
			this.$refs.searchForm.focus();
			nextTick( () => {
				this.disableTransitions = false;
			} );
		}
	}
} );
</script>
