package com.applisto.appcloner;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import com.google.android.material.bottomsheet.BottomSheetDialogFragment;

public class ClonedAppMenuBottomSheet extends BottomSheetDialogFragment {

    public static final String TAG = "ClonedAppMenuBottomSheet";

    private BottomSheetListener mListener;
    private MainActivity.AppInfo appInfo;

    public static ClonedAppMenuBottomSheet newInstance(MainActivity.AppInfo appInfo) {
        ClonedAppMenuBottomSheet fragment = new ClonedAppMenuBottomSheet();
        fragment.appInfo = appInfo;
        return fragment;
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container, @Nullable Bundle savedInstanceState) {
        return inflater.inflate(R.layout.bottom_sheet_menu, container, false);
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        TextView optionEditPrefs = view.findViewById(R.id.option_edit_prefs);
        TextView optionExportData = view.findViewById(R.id.option_export_data);
        TextView optionUninstall = view.findViewById(R.id.option_uninstall);

        optionEditPrefs.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onOptionClick(R.id.action_edit_prefs, appInfo);
            }
            dismiss();
        });

        optionExportData.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onOptionClick(R.id.action_export_data, appInfo);
            }
            dismiss();
        });

        optionUninstall.setOnClickListener(v -> {
            if (mListener != null) {
                mListener.onOptionClick(R.id.action_uninstall, appInfo);
            }
            dismiss();
        });
    }

    @Override
    public void onAttach(@NonNull Context context) {
        super.onAttach(context);
        if (context instanceof BottomSheetListener) {
            mListener = (BottomSheetListener) context;
        } else {
            throw new RuntimeException(context.toString()
                    + " must implement BottomSheetListener");
        }
    }

    @Override
    public void onDetach() {
        super.onDetach();
        mListener = null;
    }

    public interface BottomSheetListener {
        void onOptionClick(int optionId, MainActivity.AppInfo appInfo);
    }
}
